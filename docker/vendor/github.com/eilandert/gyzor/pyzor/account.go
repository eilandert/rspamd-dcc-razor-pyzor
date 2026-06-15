// Package pyzor implements the Pyzor client wire protocol (the subset gyzor
// needs: check, report, whitelist, ping) over UDP, byte-compatible with the
// reference pyzor client so the public servers accept gyzor's requests.
//
// Reference: pyzor 1.1.2 — pyzor/account.py, pyzor/message.py, pyzor/client.py.
package pyzor

import (
	"crypto/sha1" // #nosec G505 -- pyzor wire protocol mandates SHA1; not a security primitive here
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	protoName     = "pyzor"
	protoVersion  = "2.1"
	anonymousUser = "anonymous"
)

// Account is a client identity. The zero value / Anonymous is used when no
// accounts file matches the server.
type Account struct {
	Username string
	Salt     string
	Key      string
}

// Anonymous is the implicit account that always exists (username "anonymous",
// empty key). The docker backend uses it exclusively.
var Anonymous = Account{Username: anonymousUser, Key: ""}

// hashKey mirrors account.hash_key:  lower(SHA1(user + ":" + lower(key))).
func hashKey(key, user string) string {
	sum := sha1.Sum([]byte(user + ":" + strings.ToLower(key))) // #nosec G401 -- pyzor protocol mandates SHA1
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

// signMsg mirrors account.sign_msg:  lower(SHA1( SHA1(M).raw + ":T:K" ))
// where M is the signed message text, T the epoch timestamp and K the hashed key.
func signMsg(hashedKey string, timestamp int64, signedText string) string {
	inner := sha1.Sum([]byte(signedText)) // #nosec G401 -- pyzor protocol mandates SHA1
	outer := sha1.New()                   // #nosec G401 -- pyzor protocol mandates SHA1
	outer.Write(inner[:])
	outer.Write([]byte(fmt.Sprintf(":%d:%s", timestamp, hashedKey)))
	return strings.ToLower(hex.EncodeToString(outer.Sum(nil)))
}

// keyFromHexStr splits a "salt,key" accounts-file field, mirroring
// account.key_from_hexstr.
func keyFromHexStr(s string) (salt, key string, err error) {
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid key %q: missing comma salt divider", s)
	}
	return parts[0], parts[1], nil
}
