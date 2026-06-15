package gozer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Engine is the backend the server dispatches to. *Backends is the production
// implementation; tests inject a fake to exercise the HTTP layer without live
// razor/pyzor network calls.
type Engine interface {
	Check(msg []byte) Verdict
	Report(msg []byte) ReportResult
	Revoke(msg []byte) ReportResult
	HasRazorIdentity() bool
}

// Server is the HTTP front-end: auth, body limits, the bounded-concurrency
// gate, the /check verdict cache, and fail-open dispatch to the engine.
type Server struct {
	cfg     *Config
	engine  Engine
	cache   Cache
	sem     chan struct{}
	metrics *Metrics
}

// NewServer builds the server, its backends and its cache from cfg.
func NewServer(cfg *Config) *Server {
	cfg.sanitize() // re-clamp after any CLI-flag overlay so make(chan) can't panic
	s := &Server{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent), metrics: NewMetrics()}
	b := NewBackends(cfg, s.logf)
	b.metrics = s.metrics
	s.engine = b
	s.cache = NewCache(cfg, s.logf)
	return s
}

// NewServerWithEngine builds a server around a supplied engine and cache (for
// tests). A nil cache disables caching.
func NewServerWithEngine(cfg *Config, engine Engine, cache Cache) *Server {
	cfg.sanitize()
	return &Server{cfg: cfg, engine: engine, cache: cache, sem: make(chan struct{}, cfg.MaxConcurrent), metrics: NewMetrics()}
}

// #nosec G706 -- callers pass internal constant format strings; args are
// numbers and JSON (encoding/json escapes control chars), never raw message bytes.
func (s *Server) logf(format string, a ...any) { log.Printf("[gozer] "+format, a...) }

func (s *Server) vlogf(format string, a ...any) {
	if s.cfg.Verbose {
		s.logf(format, a...)
	}
}

// ListenAndServe binds and serves until the process is signalled.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second, // Slowloris guard
		// Bound a slow client holding the body or the response: a request must
		// arrive and be answered within the backend budget plus slack, and idle
		// keep-alive connections are reaped.
		ReadTimeout:  s.cfg.BackendTimeout + 20*time.Second,
		WriteTimeout: s.cfg.BackendTimeout + 25*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.logStartup(addr)
	return srv.ListenAndServe()
}

func (s *Server) logStartup(addr string) {
	if s.cfg.Token == "" {
		s.logf("WARNING: no GOZER_TOKEN configured — POST endpoints will refuse all " +
			"requests (503). Set GOZER_TOKEN or GOZER_TOKEN_FILE.")
	}
	cache := "off"
	if s.cache != nil {
		cache = "memory"
		if s.cfg.RedisURL != "" {
			cache = "redis"
		}
	}
	s.logf("listening on %s (timeout=%s, max_concurrent=%d, cache=%s ttl=%s, "+
		"razor_identity=%t, verbose=%t, auth=%t)",
		addr, s.cfg.BackendTimeout, s.cfg.MaxConcurrent, cache, s.cfg.CacheTTL,
		s.engine.HasRazorIdentity(), s.cfg.Verbose, s.cfg.Token != "")
	// Under verbose, dump the full resolved config (no secrets) so an operator
	// can confirm env/flag overrides took effect.
	s.vlogf("config: pyzor_home=%s razor_home=%s min_cf=%s dcc_servers=%q "+
		"pyzor_servers=%q razor_discovery=%q cache_size=%d redis=%t max_body=%dB",
		s.cfg.PyzorHome, s.cfg.RazorHome, s.cfg.MinCf, s.cfg.DCCServers,
		s.cfg.PyzorServers, s.cfg.RazorDiscovery, s.cfg.CacheSize,
		s.cfg.RedisURL != "", s.cfg.MaxBody)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeText(w, http.StatusOK, "ok")
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		s.metrics.ServeHTTP(w, r)
	case r.Method == http.MethodPost && isBackendPath(r.URL.Path):
		s.handlePost(w, r)
	default:
		writeText(w, http.StatusNotFound, "not found")
	}
}

func isBackendPath(p string) bool {
	return p == "/check" || p == "/report" || p == "/revoke"
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	// Auth: fail closed if no token is configured (503), reject a wrong/absent
	// token (401). The backend never runs unauthenticated.
	ok, configured := s.authed(r)
	if !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gozer token not configured"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	path := r.URL.Path
	s.metrics.incPath(path)

	// Validate the declared length cheaply (no read yet) — reject anything
	// missing, non-positive, or over the body cap.
	length, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil || length <= 0 || length > s.cfg.MaxBody {
		s.metrics.inc(&s.metrics.errorTotal)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad length"})
		return
	}

	// Acquire a concurrency slot BEFORE buffering the (up to MaxBody) body, so a
	// burst of large uploads cannot hold unbounded goroutines/memory while never
	// consuming a slot. Each request opens razor/pyzor/DCC sockets downstream.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-time.After(s.cfg.BackendTimeout):
		s.metrics.inc(&s.metrics.busyTotal)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		s.logf("%s 503 busy (max_concurrent=%d reached)", path, s.cfg.MaxConcurrent)
		return
	}

	msg, err := io.ReadAll(io.LimitReader(r.Body, length))
	if err != nil {
		s.metrics.inc(&s.metrics.errorTotal)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read error"})
		return
	}
	t0 := time.Now()
	defer s.metrics.observeSince(t0)

	// /check is a cacheable idempotent query; /report and /revoke never cache and
	// invalidate any cached /check verdict for the same message.
	var cacheKey string
	if s.cache != nil {
		cacheKey = sha256hex(msg)
	}
	if path == "/check" && cacheKey != "" {
		if hit, found := s.cache.Get(cacheKey); found {
			s.metrics.inc(&s.metrics.cacheHit)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-DRP-Cache", "hit")
			w.Header().Set("Content-Length", strconv.Itoa(len(hit)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(hit)
			s.vlogf("/check %dB cache=hit %.1fms -> %s", len(msg), msSince(t0), hit)
			return
		}
		s.metrics.inc(&s.metrics.cacheMiss)
	}

	body := s.dispatch(path, msg)
	switch {
	case path == "/check" && cacheKey != "":
		s.cache.Put(cacheKey, body)
	case (path == "/report" || path == "/revoke") && cacheKey != "":
		// the message's spam status just changed — drop the stale /check verdict
		s.cache.Delete(cacheKey)
	}
	writeRaw(w, http.StatusOK, "application/json", body)

	if path == "/check" {
		s.vlogf("/check %dB cache=miss %.1fms -> %s", len(msg), msSince(t0), body) // high volume
	} else {
		// /report + /revoke are rare feedback actions — always log (audit trail).
		s.logf("%s %dB %.1fms -> %s", path, len(msg), msSince(t0), body)
	}
}

// dispatch runs the backend for path and marshals the verdict. It never lets a
// backend panic reach the caller: on panic it logs and returns safe defaults
// (the rspamd plugin must never see a 500).
func (s *Server) dispatch(path string, msg []byte) (body []byte) {
	defer func() {
		if rec := recover(); rec != nil {
			s.logf("%s backend panic: %v", path, rec)
			body = defaultJSON(path)
		}
	}()
	var v any
	switch path {
	case "/check":
		v = s.engine.Check(msg)
	case "/report":
		v = s.engine.Report(msg)
	case "/revoke":
		v = s.engine.Revoke(msg)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return defaultJSON(path)
	}
	return b
}

func defaultJSON(path string) []byte {
	var b []byte
	if path == "/check" {
		b, _ = json.Marshal(DefaultVerdict())
	} else {
		b, _ = json.Marshal(DefaultReport())
	}
	return b
}

// authed validates the shared secret. configured is false when no token is set
// (caller returns 503); ok is the constant-time comparison result.
func (s *Server) authed(r *http.Request) (ok, configured bool) {
	if s.cfg.Token == "" {
		return false, false
	}
	presented := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		presented = strings.TrimSpace(a[len("Bearer "):])
	} else {
		presented = strings.TrimSpace(r.Header.Get("X-DRP-Token"))
	}
	return hmac.Equal([]byte(presented), []byte(s.cfg.Token)), true
}

// --- response helpers ---

func writeText(w http.ResponseWriter, code int, body string) {
	writeRaw(w, code, "text/plain", []byte(body))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"internal"}`)
	}
	writeRaw(w, code, "application/json", b)
}

func writeRaw(w http.ResponseWriter, code int, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body) // #nosec G705 -- application/json (or text/plain) API response, not an HTML/XSS sink
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
