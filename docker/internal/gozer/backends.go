package gozer

import (
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/eilandert/gazor/razor"
	"github.com/eilandert/gdcc/dcc"
	"github.com/eilandert/gyzor/pyzor"
)

// Verdict is the /check response: one sub-object per network.
type Verdict struct {
	DCC   DCCResult   `json:"dcc"`
	Razor RazorResult `json:"razor"`
	Pyzor PyzorResult `json:"pyzor"`
}

// DCCResult mirrors the original Python implementation: an action plus the bulk body count (null
// when DCC did not report one).
type DCCResult struct {
	Action string `json:"action"` // "reject" | "accept" | "unknown"
	Bulk   *int   `json:"bulk"`
}

// RazorResult is the razor verdict.
type RazorResult struct {
	Hit bool `json:"hit"`
}

// PyzorResult is the pyzor verdict: report count and whitelist count.
type PyzorResult struct {
	Count int `json:"count"`
	WL    int `json:"wl"`
}

// ReportResult is the /report and /revoke response. DCC is a pointer so it can
// be JSON null: /revoke always reports dcc=null (DCC has no network un-report).
// /report reports true/false (gdcc is in-process and always attempts the send).
type ReportResult struct {
	DCC   *bool `json:"dcc"`
	Razor bool  `json:"razor"`
	Pyzor bool  `json:"pyzor"`
}

// DefaultVerdict is the fail-open /check answer used when a request handler
// panics: every network reports its safe (non-spam / unknown) value.
func DefaultVerdict() Verdict {
	return Verdict{DCC: DCCResult{Action: "unknown"}}
}

// DefaultReport is the fail-open /report or /revoke answer (nothing reported).
func DefaultReport() ReportResult { return ReportResult{} }

// Backends runs the three collaborative-filter networks, all in-process:
// gazor (Razor), gyzor (Pyzor) and gdcc (DCC). A nil logf is tolerated.
type Backends struct {
	cfg   *Config
	pyzor *pyzor.Client
	dcc   *dcc.Client
	ident *razor.Identity // nil => report/revoke unavailable for razor
	logf  func(string, ...any)
}

// NewBackends wires the pyzor client (servers/accounts loaded from PyzorHome)
// and the razor identity (if configured). logf is the always-on logger: backend
// errors are always logged through it; gazor/gyzor are pointed at it too and
// emit their own per-operation debug lines only when cfg.Verbose is set.
func NewBackends(cfg *Config, logf func(string, ...any)) *Backends {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	b := &Backends{cfg: cfg, logf: logf}
	b.pyzor = pyzor.New(pyzor.Config{
		Home:    cfg.PyzorHome,
		Timeout: cfg.BackendTimeout,
		Verbose: cfg.Verbose,
		Log:     func(line string) { logf("%s", line) },
	})
	// DCC identity: explicit env id/pass win, else DCC_IDS / /var/dcc/ids, else
	// anonymous. Servers default to the public pool when DCC_SERVERS is empty.
	id := dcc.ResolveIdentity(cfg.DCCClientID, cfg.DCCClientPass)
	b.dcc = &dcc.Client{
		Servers:  parseDCCServers(cfg.DCCServers),
		ClientID: id.ClientID,
		Password: id.Password,
		Timeout:  cfg.BackendTimeout,
		Verbose:  cfg.Verbose,
		Log:      func(line string) { logf("%s", line) },
	}
	if cfg.RazorUser != "" && cfg.RazorPass != "" {
		b.ident = &razor.Identity{User: cfg.RazorUser, Pass: cfg.RazorPass}
	}
	return b
}

// HasRazorIdentity reports whether report/revoke can reach razor.
func (b *Backends) HasRazorIdentity() bool { return b.ident != nil }

// razorClient builds a fresh client per call: razor.Client.Check/Report/Revoke
// each open and close their own connection, so the value is single-use. The
// client logs through gozer's logger (errors always; debug when Verbose).
func (b *Backends) razorClient() *razor.Client {
	return &razor.Client{
		Timeout: b.cfg.BackendTimeout,
		MinCf:   b.cfg.MinCf,
		Ident:   b.ident,
		Verbose: b.cfg.Verbose,
		Log:     func(line string) { b.logf("%s", line) },
	}
}

// Check queries all three networks concurrently. It seeds the safe defaults so
// a backend that panics (recovered in runParallel) leaves its sub-verdict at
// the non-spam/unknown value rather than a bare zero value.
func (b *Backends) Check(msg []byte) Verdict {
	v := DefaultVerdict()
	runParallel(
		func() { v.DCC = b.checkDCC(msg) },
		func() { v.Razor = b.checkRazor(msg) },
		func() { v.Pyzor = b.checkPyzor(msg) },
	)
	return v
}

// Report submits the message as spam to all three networks concurrently.
func (b *Backends) Report(msg []byte) ReportResult {
	var r ReportResult
	runParallel(
		func() { r.DCC = b.reportDCC(msg) },
		func() { r.Razor = b.reportRazor(msg) },
		func() { r.Pyzor = b.pyzor.Report(msg) },
	)
	return r
}

// Revoke reports the message as ham where the network supports it. DCC has no
// network un-report, so dcc is always null.
func (b *Backends) Revoke(msg []byte) ReportResult {
	var r ReportResult // r.DCC stays nil -> JSON null
	runParallel(
		func() { r.Razor = b.revokeRazor(msg) },
		func() { r.Pyzor = b.pyzor.Whitelist(msg) },
	)
	return r
}

// --- DCC (gdcc, in-process) ---

func (b *Backends) checkDCC(msg []byte) DCCResult {
	res, err := b.dcc.Check(msg)
	if err != nil {
		return DCCResult{Action: "unknown"} // gdcc already logged the error
	}
	// A body checksum at DCC "many" rejects (matches dccproc's default
	// threshold); a server whitelist accepts; otherwise no opinion.
	v := res.Verdict()
	return DCCResult{Action: v.Action.String(), Bulk: v.Bulk}
}

func (b *Backends) reportDCC(msg []byte) *bool {
	ok := b.dcc.Report(msg) == nil // gdcc logs the error itself
	return &ok
}

// parseDCCServers turns "h1,h2:6277,[::1]:6277" into gdcc servers. Empty -> nil
// (gdcc then uses the public anonymous pool).
func parseDCCServers(spec string) []dcc.Server {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var out []dcc.Server
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port := item, 0
		if h, p, err := net.SplitHostPort(item); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		} else if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
			host = item[1 : len(item)-1]
		}
		out = append(out, dcc.Server{Host: host, Port: port})
	}
	return out
}

// --- Razor (gazor, in-process) ---

func (b *Backends) checkRazor(msg []byte) RazorResult {
	hit, err := b.razorClient().Check(msg)
	if err != nil {
		return RazorResult{Hit: false} // gazor already logged the error
	}
	return RazorResult{Hit: hit}
}

func (b *Backends) reportRazor(msg []byte) bool {
	if b.ident == nil {
		return false
	}
	if err := b.razorClient().Report(msg); err != nil {
		return false // gazor already logged the error
	}
	return true
}

func (b *Backends) revokeRazor(msg []byte) bool {
	if b.ident == nil {
		return false
	}
	if err := b.razorClient().Revoke(msg); err != nil {
		return false // gazor already logged the error
	}
	return true
}

// --- Pyzor (gyzor, in-process) ---

func (b *Backends) checkPyzor(msg []byte) PyzorResult {
	// gyzor aggregates across servers (Count/Whitelist are the max across
	// successful servers, the pyzor-correct semantics) and degrades to zero on
	// unreachable servers, so there is no error path here.
	res := b.pyzor.Check(msg)
	return PyzorResult{Count: res.Count, WL: res.Whitelist}
}

// runParallel runs fns concurrently and waits for all to finish. Each fn is
// guarded by a recover so a panicking backend never crashes gozer or aborts
// its siblings; the panicking backend simply leaves its result at the seeded
// default (fail-open).
func runParallel(fns ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for _, fn := range fns {
		go func(f func()) {
			defer wg.Done()
			defer func() { _ = recover() }()
			f()
		}(fn)
	}
	wg.Wait()
}
