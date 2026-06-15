package razor

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultHomeDirName is the conventional Razor2 home directory under $HOME.
const DefaultHomeDirName = ".razor"

// ResolveHome returns the Razor2 home directory using razor's resolution order:
// the explicit flagHome → $RAZOR_HOME → ~/.razor.
func ResolveHome(flagHome string) string {
	if flagHome != "" {
		return flagHome
	}
	if h := os.Getenv("RAZOR_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, DefaultHomeDirName)
	}
	return DefaultHomeDirName
}

// ParseIdentityFile reads a Razor2 identity file (key=value lines, '#'
// comments, per Razor2::Client::Config::read_file) and returns the user/pass.
// It returns ok=false if both fields are not present.
func ParseIdentityFile(r io.Reader) (Identity, bool) {
	var id Identity
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "user":
			id.User = strings.TrimSpace(v)
		case "pass":
			id.Pass = strings.TrimSpace(v)
		}
	}
	if id.User == "" || id.Pass == "" {
		return Identity{}, false
	}
	return id, true
}

// ResolveIdentity applies the standard fallback chain for report/revoke
// credentials and returns the identity to use, or nil for anonymous (check
// works without an identity):
//
//	GAZOR_USER + GAZOR_PASS env
//	→ RAZOR_USER + RAZOR_PASS env (razor-agent compatible)
//	→ <home>/identity file (key=value)
//	→ nil
//
// flagUser/flagPass (e.g. from CLI flags) take precedence when both are set.
func ResolveIdentity(flagUser, flagPass, home string) *Identity {
	if flagUser != "" && flagPass != "" {
		return &Identity{User: flagUser, Pass: flagPass}
	}
	if u, p := os.Getenv("GAZOR_USER"), os.Getenv("GAZOR_PASS"); u != "" && p != "" {
		return &Identity{User: u, Pass: p}
	}
	if u, p := os.Getenv("RAZOR_USER"), os.Getenv("RAZOR_PASS"); u != "" && p != "" {
		return &Identity{User: u, Pass: p}
	}
	f, err := os.Open(filepath.Join(home, "identity")) // #nosec G304 -- operator-provided razor home (flag/env/default), not attacker input
	if err != nil {
		return nil
	}
	defer f.Close()
	if id, ok := ParseIdentityFile(f); ok {
		return &id
	}
	return nil
}
