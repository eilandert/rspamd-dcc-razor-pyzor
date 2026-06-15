// Command gozer is the standalone DCC/Razor/Pyzor backend for rspamd. It
// imports gazor (razor) and gyzor (pyzor) in-process and runs DCC via the
// dccproc CLI, replacing the earlier original Python implementation that forked the perl razor and
// python pyzor CLIs per message.
//
// Usage:
//
//	gozer [serve]               run the HTTP backend on GOZER_HOST:GOZER_PORT
//	gozer razor-register [...]  obtain a razor identity and persist it
//	gozer version               print the version
//
// razor-register is used by the container's init-bootstrap to create/persist
// the razor credential gozer needs for /report and /revoke.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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
		return cmdServe()
	case "razor-register":
		return cmdRegister(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: gozer [serve|razor-register|version]")
		return 2
	}
}

func cmdServe() int {
	srv := gozer.NewServer(gozer.LoadConfig())
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
