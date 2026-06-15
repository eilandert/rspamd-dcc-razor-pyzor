package dcc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultServer is one host of the public anonymous DCC server pool. The bare
// "dcc.dcc-servers.net" no longer resolves; the pool is dcc1..dccN. DefaultServers
// lists a few for redundancy.
const DefaultServer = "dcc1.dcc-servers.net"

// DefaultServers is the fallback server list when Client.Servers is empty.
var DefaultServers = []Server{
	{Host: "dcc1.dcc-servers.net"},
	{Host: "dcc2.dcc-servers.net"},
	{Host: "dcc3.dcc-servers.net"},
	{Host: "dcc4.dcc-servers.net"},
}

const (
	maxXmits       = 4 // DCC_MAX_XMITS
	defaultTimeout = 5 * time.Second
)

// Server is a DCC server endpoint. Port 0 means the default 6277.
type Server struct {
	Host string
	Port int
}

func (s Server) port() int {
	if s.Port == 0 {
		return dccSrvrPort
	}
	return s.Port
}

// Client talks to DCC servers. The zero value is usable: it queries the public
// anonymous pool. Mirror of the gazor/gyzor Client shape.
type Client struct {
	Servers  []Server      // default: {DefaultServer, 6277}
	ClientID uint32        // 1 = anonymous (default)
	Password string        // for authenticated client-ids; empty = anonymous
	Timeout  time.Duration // total per-server budget; default 5s
	Verbose  bool          // log debug lines via Log
	Log      func(string)  // log sink; nil → stderr. Errors always logged.

	once sync.Once // guards hid/pid init (Client may be shared across goroutines)
	hid  uint32    // op_nums.h, randomised once
	pid  uint32    // op_nums.p
	rid  uint32    // op_nums.r, atomic
}

func (c *Client) logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	if c.Log != nil {
		c.Log(line)
	} else {
		fmt.Fprintln(os.Stderr, "dcc: "+line)
	}
}

func (c *Client) vlogf(format string, args ...interface{}) {
	if c.Verbose {
		c.logf(format, args...)
	}
}

func (c *Client) servers() []Server {
	if len(c.Servers) == 0 {
		return DefaultServers
	}
	return c.Servers
}

// sender returns the client-id and signing password. An id other than anon
// with an empty password falls back to anonymous, as the C client does.
func (c *Client) sender() (uint32, []byte) {
	id := c.ClientID
	if id == 0 {
		id = dccIDAnon
	}
	if id == dccIDAnon || c.Password == "" {
		return dccIDAnon, nil
	}
	return id, passwd16(c.Password)
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

// ensureIDs lazily fills the per-client transaction identifiers exactly once,
// safely even when the Client is shared across goroutines (e.g. serve mode).
func (c *Client) ensureIDs() {
	c.once.Do(func() {
		var b [8]byte
		_, _ = rand.Read(b[:])
		h := binary.LittleEndian.Uint32(b[0:4])
		if h == 0 {
			h = 1
		}
		c.hid = h
		p := binary.LittleEndian.Uint32(b[4:8])
		if p == 0 {
			p = uint32(os.Getpid()) // #nosec G115 -- pid fits the opaque 32-bit op_nums field
		}
		c.pid = p
	})
}

// Check queries the DCC servers for the message's checksums and returns the
// per-checksum counts. It does not increment any counts.
func (c *Client) Check(msg []byte) (Result, error) {
	cks := Checksums(msg)
	return c.send(opQuery, 0, cks)
}

// Report submits the message's checksums to the DCC servers, incrementing the
// counts by recipients (default 1). Use ReportN for a specific recipient count.
func (c *Client) Report(msg []byte) error {
	return c.ReportN(msg, 1)
}

// ReportN reports the message as received by n recipients.
func (c *Client) ReportN(msg []byte, n uint32) error {
	if n == 0 {
		n = 1
	}
	cks := Checksums(msg)
	_, err := c.send(opReport, n, cks)
	return err
}

// send builds the query/report, transmits it to each server in turn with
// retransmission, and decodes the first valid answer.
func (c *Client) send(op int, tgts uint32, cks []Checksum) (Result, error) {
	n := reportableCount(cks)
	if n == 0 {
		return Result{}, fmt.Errorf("dcc: no reportable checksums (body too short?)")
	}
	c.ensureIDs()
	sender, passwd := c.sender()
	nums := opNums{
		h: c.hid,
		p: c.pid,
		r: atomic.AddUint32(&c.rid, 1),
	}

	servers := c.servers()

	// Reports must reach a single server: the inter-server flooding algorithm
	// dedups by (sender,h,p,r), and racing a report to several servers would be
	// counted as separate copies. So reports go sequentially, advancing only
	// when a server gives no answer at all. Queries are safe to race for
	// resilience against a slow/dead first server.
	if op == opQuery && len(servers) > 1 {
		return c.parallelQuery(servers, op, sender, nums, tgts, cks, passwd, n)
	}

	var lastErr error
	for _, srv := range servers {
		counts, err := c.exchange(nil, srv, op, sender, nums, tgts, cks, passwd, n)
		if err == nil {
			return c.buildResult(cks, counts), nil
		}
		c.vlogf("server %s: %v", srv.Host, err)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dcc: no servers configured")
	}
	c.logf("query failed: %v", lastErr)
	return Result{}, lastErr
}

// parallelQuery races a query across all servers and returns the first valid
// answer, signalling the losing goroutines to stop.
func (c *Client) parallelQuery(servers []Server, op int, sender uint32, nums opNums, tgts uint32, cks []Checksum, passwd []byte, n uint32) (Result, error) {
	type res struct {
		counts []answerCount
		err    error
	}
	stop := make(chan struct{})
	out := make(chan res, len(servers))
	for _, srv := range servers {
		go func(srv Server) {
			counts, err := c.exchange(stop, srv, op, sender, nums, tgts, cks, passwd, n)
			out <- res{counts, err}
		}(srv)
	}

	var lastErr error
	for i := 0; i < len(servers); i++ {
		r := <-out
		if r.err == nil {
			close(stop) // tell the losers to quit; buffered out absorbs them
			return c.buildResult(cks, r.counts), nil
		}
		lastErr = r.err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dcc: no servers configured")
	}
	c.logf("query failed: %v", lastErr)
	return Result{}, lastErr
}

// exchange handles one server: resolve, send, retransmit with exponential
// backoff up to maxXmits, and wait for a matching answer within the budget.
func (c *Client) exchange(stop <-chan struct{}, srv Server, op int, sender uint32, nums opNums, tgts uint32, cks []Checksum, passwd []byte, n uint32) ([]answerCount, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(srv.Host, fmt.Sprint(srv.port())))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", srv.Host, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", srv.Host, err)
	}
	defer conn.Close()

	pkt := buildQuery(op, sender, nums, tgts, cks, passwd)
	budget := c.timeout()
	deadline := time.Now().Add(budget)
	backoff := budget / (1 << maxXmits) // first wait; doubles each retransmit
	if backoff < 50*time.Millisecond {
		backoff = 50 * time.Millisecond
	}

	for xmit := 0; xmit < maxXmits; xmit++ {
		select {
		case <-stop:
			return nil, errStopped
		default:
		}

		nums.t++
		binary.BigEndian.PutUint32(pkt[20:24], nums.t)
		signPacket(pkt, passwd)

		if _, err := conn.Write(pkt); err != nil {
			return nil, fmt.Errorf("send: %w", err)
		}
		c.vlogf("%s xmit %d to %s (%d checksums)", opName(op), xmit+1, srv.Host, n)

		waitUntil := time.Now().Add(backoff)
		if waitUntil.After(deadline) {
			waitUntil = deadline
		}
		counts, err := c.readAnswer(stop, conn, n, nums, passwd, waitUntil)
		if err == nil {
			return counts, nil
		}
		if err != errTimeout {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			break
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("no answer from %s after %v", srv.Host, budget)
}

// readAnswer reads datagrams until a matching answer arrives or the deadline
// passes. Stray/late datagrams (wrong transaction id) are skipped.
func (c *Client) readAnswer(stop <-chan struct{}, conn *net.UDPConn, n uint32, nums opNums, passwd []byte, until time.Time) ([]answerCount, error) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-stop:
			return nil, errStopped
		default:
		}
		if !time.Now().Before(until) {
			return nil, errTimeout
		}
		_ = conn.SetReadDeadline(until)
		rn, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, errTimeout
			}
			return nil, fmt.Errorf("recv: %w", err)
		}
		counts, err := parseAnswer(buf[:rn], n, nums)
		if err == errMismatch {
			continue // not our transaction; keep waiting
		}
		if err != nil {
			return nil, err
		}
		// For an authenticated client the server signs the answer with our
		// password; an answer that does not verify is spoofed or corrupt — skip
		// it and keep waiting (a genuine answer may still arrive) rather than
		// trusting its counts. Anonymous answers carry a zero signature and pass.
		if !verifyAnswerSig(buf[:rn], passwd) {
			c.vlogf("answer from server failed signature verification; ignoring")
			continue
		}
		return counts, nil
	}
}

// buildResult pairs the answer counts with the reportable checksums, in order.
func (c *Client) buildResult(cks []Checksum, counts []answerCount) Result {
	var out []CkCount
	i := 0
	for _, ck := range cks {
		if !ck.Report || i >= len(counts) {
			continue
		}
		out = append(out, CkCount{
			Type:  ck.Type,
			Label: ck.Label,
			Cur:   counts[i].cur,
			Prev:  counts[i].prev,
		})
		i++
	}
	return Result{Counts: out}
}

var errTimeout = fmt.Errorf("dcc: timeout")

// errStopped: a parallel query was already answered by another server.
var errStopped = fmt.Errorf("dcc: stopped")

func opName(op int) string {
	switch op {
	case opQuery:
		return "query"
	case opReport:
		return "report"
	case opNop:
		return "nop"
	}
	return "op"
}
