package dcc

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// Identity is a DCC client credential: a numeric client-id and its password.
// The anonymous identity is {ClientID: 1, Password: ""}.
type Identity struct {
	ClientID uint32
	Password string
}

// Anonymous reports whether this identity is the unauthenticated client.
func (id Identity) Anonymous() bool { return id.ClientID <= dccIDAnon || id.Password == "" }

// DefaultIDsPath is the conventional DCC identity file.
const DefaultIDsPath = "/var/dcc/ids"

// ParseIdentityFile reads the first usable non-anonymous client identity from a
// DCC ids-format stream. Lines are "id[,options] passwd1 [passwd2]"; '#' starts
// a comment; blank lines are ignored. Only the current (first) password is used.
func ParseIdentityFile(r io.Reader) (Identity, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// the id may carry ",option=..." suffixes — keep the leading number
		idTok := fields[0]
		if i := strings.IndexByte(idTok, ','); i >= 0 {
			idTok = idTok[:i]
		}
		n, err := strconv.ParseUint(idTok, 10, 32)
		if err != nil || n <= dccIDAnon {
			continue
		}
		return Identity{ClientID: uint32(n), Password: fields[1]}, true
	}
	return Identity{}, false
}

// ResolveIdentity applies the standard fallback chain and returns the client
// identity to use:
//
//	GDCC_CLIENT_ID + GDCC_CLIENT_PASSWD env
//	→ DCC_IDS env (path to an ids file)
//	→ /var/dcc/ids
//	→ anonymous (id 1)
//
// The supplied id/passwd (e.g. from CLI flags) take precedence when non-empty.
func ResolveIdentity(flagID uint32, flagPasswd string) Identity {
	if flagID > dccIDAnon && flagPasswd != "" {
		return Identity{ClientID: flagID, Password: flagPasswd}
	}
	if envID := envClientID(); envID > dccIDAnon {
		if pw := os.Getenv("GDCC_CLIENT_PASSWD"); pw != "" {
			return Identity{ClientID: envID, Password: pw}
		}
	}
	paths := []string{}
	if p := os.Getenv("DCC_IDS"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, DefaultIDsPath)
	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304 G703 -- operator-provided ids path (env/default), not attacker input
		if err != nil {
			continue
		}
		id, ok := ParseIdentityFile(f)
		_ = f.Close()
		if ok {
			return id
		}
	}
	return Identity{ClientID: dccIDAnon}
}

func envClientID() uint32 {
	if v := os.Getenv("GDCC_CLIENT_ID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 0
}
