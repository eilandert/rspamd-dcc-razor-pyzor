// Command gozer is the standalone DCC/Razor/Pyzor backend for rspamd. It speaks
// all three networks in-process — gazor (razor), gyzor (pyzor) and gdcc (DCC) —
// replacing the earlier Python implementation that forked the perl razor,
// python pyzor and dccproc CLIs per message.
//
// Usage:
//
//	gozer [serve] [flags]       run the HTTP backend on GOZER_HOST:GOZER_PORT
//	gozer stats                 fetch and print the local /metrics exposition
//	gozer health                probe the local /health endpoint (HEALTHCHECK)
//	gozer razor-register [...]  obtain a razor identity and persist it
//	gozer version               print the version
//
// Every serve option is settable by env var OR CLI flag (flag > env > default);
// see cmdServe for the flag set. razor-register obtains the razor credential
// gozer needs for /report and /revoke; pass it back via RAZOR_USER/RAZOR_PASS
// (or their _FILE forms).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eilandert/gazor/razor"
	"github.com/eilandert/rspamd-dcc-razor-pyzor/internal/gozer"
)

var version = "dev"

func main() {
	log.SetFlags(0) // s6 / journald add their own timestamps
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version", "-v":
			fmt.Println("gozer", version)
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			cmd, args = args[0], args[1:]
		}
	}
	switch cmd {
	case "serve":
		return cmdServe(args)
	case "stats":
		return cmdStats()
	case "health":
		return cmdHealth()
	case "razor-register":
		return cmdRegister(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: gozer [serve|stats|health|razor-register|version]")
		return 2
	}
}

// cmdStats fetches the local /metrics exposition and prints it. Like cmdHealth
// it reuses GOZER_HOST/GOZER_PORT and needs no shell/curl in the image.
func cmdStats() int {
	cfg := gozer.LoadConfig()
	host := cfg.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + host + ":" + strconv.Itoa(cfg.Port) + "/metrics"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "stats: status", resp.StatusCode)
		return 1
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
		return 1
	}
	return 0
}

// cmdHealth probes the local /health endpoint and exits 0/1. It is the
// container HEALTHCHECK in the distroless image, which ships no shell or curl;
// it reads the same GOZER_HOST/GOZER_PORT the server binds.
func cmdHealth() int {
	cfg := gozer.LoadConfig()
	host := cfg.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + host + ":" + strconv.Itoa(cfg.Port) + "/health"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "health: status", resp.StatusCode)
		return 1
	}
	return 0
}

// cmdServe loads the config from the environment, then overlays any CLI flags
// (flag > env > default) so every option has both forms, and runs the server.
func cmdServe(args []string) int {
	cfg := gozer.LoadConfig()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Host, "host", cfg.Host, "HTTP bind host (GOZER_HOST); serves /check,/report,/revoke,/metrics,/health")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "HTTP bind port (GOZER_PORT, default 8077)")
	fs.DurationVar(&cfg.BackendTimeout, "backend-timeout", cfg.BackendTimeout, "per-request backend budget (GOZER_BACKEND_TIMEOUT)")
	fs.IntVar(&cfg.MaxConcurrent, "max-concurrent", cfg.MaxConcurrent, "max in-flight requests (GOZER_MAX_CONCURRENT)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "shared-secret for POST endpoints (GOZER_TOKEN[_FILE])")
	fs.DurationVar(&cfg.CacheTTL, "cache-ttl", cfg.CacheTTL, "verdict cache TTL, 0 disables (GOZER_CACHE_TTL)")
	fs.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "in-memory cache entries (GOZER_CACHE_SIZE)")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "per-request + startup config logging (GOZER_VERBOSE)")
	fs.StringVar(&cfg.PyzorHome, "pyzor-home", cfg.PyzorHome, "pyzor home dir (PYZOR_HOME)")
	fs.StringVar(&cfg.RazorHome, "razor-home", cfg.RazorHome, "razor home dir (RAZORHOME)")
	fs.StringVar(&cfg.MinCf, "min-cf", cfg.MinCf, "razor min confidence (RAZOR_MIN_CF)")
	fs.StringVar(&cfg.DCCServers, "dcc-servers", cfg.DCCServers, "DCC servers, comma host[:port] (DCC_SERVERS)")
	fs.StringVar(&cfg.PyzorServers, "pyzor-servers", cfg.PyzorServers, "pyzor servers DNS-bypass, comma host[:port] (GYZOR_SERVERS)")
	fs.StringVar(&cfg.RazorDiscovery, "razor-discovery", cfg.RazorDiscovery, "razor discovery DNS-bypass, comma host[:port] (GAZOR_DISCOVERY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv := gozer.NewServer(cfg)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("[gozer] server error: %v", err)
		return 1
	}
	return 0
}

// cmdRegister obtains a razor nomination-server identity (anonymous unless
// --user is given) and, with --out, persists it as "user=...\npass=..." (0600)
// for gozer to load. The credential is also printed to stdout.
func cmdRegister(args []string) int {
	fs := flag.NewFlagSet("razor-register", flag.ContinueOnError)
	user := fs.String("user", "", "register this account (empty = anonymous)")
	pass := fs.String("pass", "", "password for --user")
	out := fs.String("out", "", "write user=/pass= to this file (0600)")
	discovery := fs.String("discovery", razor.DefaultDiscovery, "discovery server")
	timeout := fs.Duration("timeout", 15*time.Second, "network timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	c := &razor.Client{Discovery: *discovery, Timeout: *timeout}
	id, err := c.Register(*user, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "razor-register:", err)
		return 1
	}
	line := fmt.Sprintf("user=%s\npass=%s\n", id.User, id.Pass)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(line), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "razor-register: write", *out, ":", err)
			return 1
		}
	}
	fmt.Print(line)
	return 0
}
