// Package digest computes the Pyzor message digest.
//
// It is a byte-exact reimplementation of pyzor's pyzor/digest.py
// (DataDigester), so the SHA1 hex value produced here matches what the
// reference pyzor client sends to the server. Any divergence means the server
// sees a different signature and the report/check is useless, so the algorithm
// is reproduced faithfully and guarded by a parity test against real pyzor.
//
// Reference: pyzor 1.1.2, pyzor/digest.py.
package pyzor

import (
	"crypto/sha1" // #nosec G505 -- pyzor wire protocol mandates SHA1; not a security primitive here
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// Tunables, identical to pyzor/digest.py.
const (
	minLineLength  = 8 // minimum normalized line length to include
	atomicNumLines = 4 // <= this many lines -> digest the whole message
)

// digestSpec mirrors pyzor's `digest_spec = [(20, 3), (60, 3)]`: at 20% and 60%
// into the line list, take 3 lines each.
var digestSpec = [][2]int{{20, 3}, {60, 3}}

// Normalization patterns, identical to pyzor/digest.py. Order of application
// matters: long strings, then emails, then URLs, then all whitespace, then trim.
//
// pyzor runs these on Python str with the Unicode regex engine, so \s/\S use the
// Unicode whitespace set, NOT just ASCII. wsClass reproduces Python's \s: the
// Unicode White_Space property plus \x1c-\x1f (which Python's \s and str.isspace
// also treat as whitespace). Getting this wrong diverges the digest for any
// message containing NBSP, ideographic space, etc.
const wsClass = `\t\n\x0b\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

var (
	longstrPtrn = regexp.MustCompile(`[^` + wsClass + `]{10,}`)
	emailPtrn   = regexp.MustCompile(`[^` + wsClass + `]+@[^` + wsClass + `]+`)
	urlPtrn     = regexp.MustCompile(`(?i)[a-z]+:[^` + wsClass + `]+`)
	wsPtrn      = regexp.MustCompile(`[` + wsClass + `]`)
)

// Compute returns the lowercase SHA1 hex digest of msg, where msg is the raw
// RFC-822 message bytes.
func Compute(msg []byte) string {
	var lines [][]byte
	for _, payload := range digestPayloads(msg) {
		for _, line := range splitLines(payload) {
			norm := normalize(line)
			if shouldHandleLine(norm) {
				lines = append(lines, []byte(norm))
			}
		}
	}

	h := sha1.New() // #nosec G401 -- pyzor protocol mandates SHA1 for the message digest
	if len(lines) <= atomicNumLines {
		for _, ln := range lines {
			h.Write(rstrip(ln))
		}
	} else {
		for _, spec := range digestSpec {
			offset, length := spec[0], spec[1]
			start := offset * len(lines) / 100
			for i := 0; i < length; i++ {
				idx := start + i
				if idx >= 0 && idx < len(lines) {
					h.Write(rstrip(lines[idx]))
				}
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalize mirrors DataDigester.normalize: strip NULs, blank out long tokens /
// emails / URLs, remove ALL whitespace, then trim.
func normalize(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = longstrPtrn.ReplaceAllString(s, "")
	s = emailPtrn.ReplaceAllString(s, "")
	s = urlPtrn.ReplaceAllString(s, "")
	s = wsPtrn.ReplaceAllString(s, "")
	return strings.TrimFunc(s, isPySpace)
}

// isPySpace matches Python str.strip()'s whitespace set (== wsClass above). After
// wsPtrn removal there is nothing left to strip, but keep it consistent.
func isPySpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xa0, 0x1680,
		0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	if r >= 0x2000 && r <= 0x200a {
		return true
	}
	return false
}

// shouldHandleLine mirrors pyzor: min_line_length is a CHARACTER (rune) count,
// not a byte count.
func shouldHandleLine(s string) bool {
	return utf8.RuneCountInString(s) >= minLineLength
}

// rstrip removes trailing ASCII whitespace, matching Python bytes.rstrip().
func rstrip(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), " \t\n\r\x0b\x0c"))
}

// splitLines mirrors Python str.splitlines() for the line boundaries that occur
// in mail: \r\n, \r, \n, \v, \f, \x1c-\x1e, \x85, U+2028, U+2029.
func splitLines(s string) []string {
	var out []string
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			out = append(out, b.String())
			b.Reset()
		case '\r':
			out = append(out, b.String())
			b.Reset()
			if i+1 < len(runes) && runes[i+1] == '\n' {
				i++ // consume the \n of a \r\n pair
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// digestPayloads walks the MIME tree like DataDigester.digest_payloads:
//   - text/*  -> CTE+charset decoded; text/html is tag-stripped to bare text
//   - non-text leaf -> raw (undecoded) payload, as pyzor's get_payload() returns
//   - multipart container -> skipped (children are walked)
func digestPayloads(raw []byte) []string {
	m, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		// Unparseable as a message: treat the whole thing as one text payload,
		// mirroring how pyzor still digests a degenerate message body.
		return []string{string(raw)}
	}
	body := readAll(m.Body)
	return walkPart(m.Header.Get("Content-Type"), m.Header.Get("Content-Transfer-Encoding"), body)
}

func walkPart(ctypeHeader, cte string, body []byte) []string {
	mediatype, params, err := mime.ParseMediaType(ctypeHeader)
	if err != nil || ctypeHeader == "" {
		// No/!parseable Content-Type defaults to text/plain (RFC 2045).
		mediatype = "text/plain"
		params = map[string]string{}
	}
	maintype, subtype := splitMediaType(mediatype)

	if maintype == "multipart" {
		boundary := params["boundary"]
		if boundary == "" {
			// A multipart Content-Type with no boundary is NOT parsed as
			// multipart by Python (is_multipart() is False); the raw body is
			// digested as a single non-text leaf.
			return []string{string(body)}
		}
		var out []string
		mr := multipart.NewReader(strings.NewReader(string(body)), boundary)
		for {
			p, err := mr.NextRawPart() // raw: do not CTE-decode here
			if err != nil {
				break
			}
			pbody := readAll(p)
			out = append(out, walkPart(p.Header.Get("Content-Type"),
				p.Header.Get("Content-Transfer-Encoding"), pbody)...)
		}
		return out
	}

	// message/rfc822 wraps a complete embedded RFC-822 message. Python's email
	// treats it as multipart (is_multipart() is True) and msg.walk() descends
	// into the embedded message, so recurse into the body the same way.
	if maintype == "message" && subtype == "rfc822" {
		return digestPayloads(body)
	}

	if maintype == "text" {
		decoded := decodeCTE(body, cte)
		text := decodeCharset(decoded, params["charset"])
		if subtype == "html" {
			return []string{normalizeHTMLPart(text)}
		}
		return []string{text}
	}

	// Non-text leaf: pyzor's get_payload(decode=False) returns the raw body
	// text (still base64/QP encoded). Use it verbatim.
	return []string{string(body)}
}

func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func splitMediaType(mt string) (main, sub string) {
	if i := strings.IndexByte(mt, '/'); i >= 0 {
		return mt[:i], mt[i+1:]
	}
	return mt, ""
}

// decodeCTE decodes the Content-Transfer-Encoding (base64 / quoted-printable);
// 7bit/8bit/binary/none pass through unchanged.
func decodeCTE(body []byte, cte string) []byte {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		// Mirror Python's get_payload(decode=True) for base64: it calls
		// base64.b64decode with validate=False (which DISCARDS non-alphabet
		// bytes, including whitespace), and on a decode error (bad length/
		// padding) registers a defect and returns the RAW, undecoded payload.
		dec, err := base64.StdEncoding.DecodeString(filterBase64(string(body)))
		if err != nil {
			return body // decode failed -> Python yields the raw payload
		}
		return dec
	case "quoted-printable":
		dec := readAll(quotedprintable.NewReader(strings.NewReader(string(body))))
		return dec
	default:
		return body
	}
}

// filterBase64 drops every byte that is not in the standard base64 alphabet
// (incl. '=' padding), matching base64.b64decode(validate=False) which discards
// non-alphabet characters before decoding.
func filterBase64(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// decodeCharset decodes bytes to a string, matching pyzor's
// payload.decode(charset, errors="ignore"):
//   - no/ascii charset -> drop bytes >= 0x80 (Python ascii + ignore)
//   - utf-8 -> keep valid runes, drop invalid bytes (utf-8 + ignore)
//   - unknown charset -> Python raises LookupError and falls back to ascii/ignore
//   - else decode with the codec, then drop U+FFFD (approximates errors="ignore",
//     which Python drops rather than substitutes)
//
// WHATWG decoding (x/net) does NOT match this for ascii (maps to windows-1252) or
// for the ignore-vs-replace behaviour, which is why we special-case it.
func decodeCharset(b []byte, cs string) string {
	switch strings.ToLower(strings.TrimSpace(cs)) {
	case "", "ascii", "us-ascii", "ansi_x3.4-1968":
		return asciiIgnore(b)
	case "utf-8", "utf8", "utf_8":
		return utf8Ignore(b)
	}
	enc, _ := charset.Lookup(strings.ToLower(strings.TrimSpace(cs)))
	if enc == nil {
		return asciiIgnore(b)
	}
	dec, err := enc.NewDecoder().Bytes(b)
	if err != nil {
		return asciiIgnore(b)
	}
	return strings.ReplaceAll(string(dec), "�", "")
}

// asciiIgnore is Python bytes.decode("ascii", "ignore"): drop every byte >= 0x80.
func asciiIgnore(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c < 0x80 {
			out = append(out, c)
		}
	}
	return string(out)
}

// utf8Ignore is Python bytes.decode("utf-8", "ignore"): keep valid runes, drop
// invalid bytes one at a time.
func utf8Ignore(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		sb.WriteRune(r)
		i += size
	}
	return sb.String()
}

// normalizeHTMLPart mirrors DataDigester.normalize_html_part: collect text
// nodes (skipping <script>/<style>), join with single spaces.
func normalizeHTMLPart(s string) string {
	var data []string
	z := html.NewTokenizer(strings.NewReader(s))
	collect := true
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken:
			name, _ := z.TagName()
			if n := strings.ToLower(string(name)); n == "script" || n == "style" {
				collect = false
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if n := strings.ToLower(string(name)); n == "script" || n == "style" {
				collect = true
			}
		case html.TextToken:
			if collect {
				t := strings.TrimSpace(string(z.Text()))
				if t != "" {
					data = append(data, t)
				}
			}
		}
	}
	return strings.Join(data, " ")
}
