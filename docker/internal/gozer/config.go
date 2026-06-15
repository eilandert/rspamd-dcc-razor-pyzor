// Package gozer is the in-process DCC/Razor/Pyzor backend for rspamd. It exposes
// one authenticated HTTP endpoint and answers /check, /report and /revoke by
// querying the three collaborative-filter networks. All three are spoken
// in-process by Go libraries: gazor (Razor), gyzor (Pyzor) and gdcc (DCC) — no
// subprocesses, no dccproc fork.
package gozer

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is gozer's runtime configuration, populated from the environment by
// LoadConfig. The field comments name the env var each value comes from.
type Config struct {
	Host           string        // GOZER_HOST              (default 0.0.0.0)
	Port           int           // GOZER_PORT              (default 8077)
	BackendTimeout time.Duration // GOZER_BACKEND_TIMEOUT   (default 6s)
	MaxConcurrent  int           // GOZER_MAX_CONCURRENT    (default 8)
	MaxBody        int64         // fixed 8 MiB request-body cap
	Token          string        // GOZER_TOKEN[_FILE]      (required for POST)

	CacheTTL    time.Duration // GOZER_CACHE_TTL    (default 300s; 0 disables)
	CacheSize   int           // GOZER_CACHE_SIZE   (default 4096 in-memory entries)
	RedisURL    string        // GOZER_REDIS_URL    (empty -> in-process LRU only)
	RedisPrefix string        // GOZER_REDIS_PREFIX (default drp:check:)

	Verbose bool // GOZER_VERBOSE

	// Backend wiring.
	PyzorHome string // PYZOR_HOME (default /var/lib/pyzor)
	RazorHome string // RAZORHOME  (default /var/lib/razor)
	MinCf     string // RAZOR_MIN_CF (default "ac")

	// DCC (in-process via gdcc). Servers is a comma list of host[:port]; empty
	// uses the public anonymous pool. Identity falls back through DCC_IDS /
	// /var/dcc/ids to anonymous when id/pass are unset (gdcc.ResolveIdentity).
	DCCServers    string // DCC_SERVERS
	DCCClientID   uint32 // DCC_CLIENT_ID        (1 = anonymous)
	DCCClientPass string // DCC_CLIENT_PASSWD[_FILE]

	// Razor identity for /report and /revoke. Precedence: RAZOR_USER/RAZOR_PASS
	// env (or _FILE) > the gazor-identity file persisted in RazorHome by
	// `gozer razor-register`. Empty means report/revoke are unavailable
	// (anonymous /check still works).
	RazorUser string
	RazorPass string
}

// LoadConfig reads the environment into a Config, applying the documented
// defaults. The razor identity is resolved last (env first, then the persisted
// file under RazorHome).
func LoadConfig() *Config {
	c := &Config{
		Host:           envStr("GOZER_HOST", "0.0.0.0"),
		Port:           envInt("GOZER_PORT", 8077),
		BackendTimeout: envDur("GOZER_BACKEND_TIMEOUT", 6),
		MaxConcurrent:  envInt("GOZER_MAX_CONCURRENT", 8),
		MaxBody:        8 * 1024 * 1024,
		Token:          envOrFile("GOZER_TOKEN"),
		CacheTTL:       envDur("GOZER_CACHE_TTL", 300),
		CacheSize:      envInt("GOZER_CACHE_SIZE", 4096),
		RedisURL:       strings.TrimSpace(os.Getenv("GOZER_REDIS_URL")),
		RedisPrefix:    envStr("GOZER_REDIS_PREFIX", "drp:check:"),
		Verbose:        envBool("GOZER_VERBOSE"),
		PyzorHome:      envStr("PYZOR_HOME", "/var/lib/pyzor"),
		RazorHome:      envStr("RAZORHOME", "/var/lib/razor"),
		MinCf:          envStr("RAZOR_MIN_CF", "ac"),
		DCCServers:     strings.TrimSpace(os.Getenv("DCC_SERVERS")),
		DCCClientID:    uint32(envInt("DCC_CLIENT_ID", 0)), // #nosec G115 -- client-id is a 32-bit DCC field
		DCCClientPass:  envOrFile("DCC_CLIENT_PASSWD"),
	}
	c.RazorUser, c.RazorPass = loadIdentity(c.RazorHome)
	return c
}

// IdentityFile is the path of the persisted razor credential inside RazorHome.
// Its format is two lines, "user=<u>" and "pass=<p>"; it is written by
// `gozer razor-register` and read back here. The name is distinct from the
// legacy perl razor-agents "identity" file so a recycled volume never confuses
// the two formats.
const IdentityFile = "gazor-identity"

// loadIdentity resolves the razor user/pass: env (RAZOR_USER/RAZOR_PASS, each
// honouring a _FILE form) wins; otherwise the persisted gazor-identity file.
func loadIdentity(home string) (user, pass string) {
	user = envOrFile("RAZOR_USER")
	pass = envOrFile("RAZOR_PASS")
	if user != "" && pass != "" {
		return user, pass
	}
	return parseIdentityFile(home + "/" + IdentityFile)
}

// parseIdentityFile reads a "user=...\npass=..." file. A missing or
// unrecognised file yields empty strings (report/revoke then unavailable).
func parseIdentityFile(path string) (user, pass string) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- operator state dir (RazorHome), not attacker input
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "user":
			user = v
		case "pass":
			pass = v
		}
	}
	return user, pass
}

// --- env helpers ---

// envOrFile returns the trimmed contents of $<name>_FILE if that file exists,
// else the trimmed value of $<name>. Mirrors the shell resolve() in
// init-bootstrap so secrets work the same way (Docker secrets via _FILE).
func envOrFile(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil { // #nosec G304 G703 -- operator-provided secret path (*_FILE env), not attacker input
			return strings.TrimSpace(string(b))
		}
	}
	return strings.TrimSpace(os.Getenv(name))
}

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return n
	}
	return def
}

// envDur reads a value expressed in seconds (float, matching the original Python implementation)
// into a Duration.
func envDur(name string, defSecs float64) time.Duration {
	secs := defSecs
	if f, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil {
		secs = f
	}
	return time.Duration(secs * float64(time.Second))
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
