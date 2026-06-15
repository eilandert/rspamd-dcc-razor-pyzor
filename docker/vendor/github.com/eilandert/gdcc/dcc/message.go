package dcc

import "bytes"

// splitHeadersBody splits a raw RFC-822 message into its unfolded header fields
// and the raw body, mirroring dccproc's get_hdr()/main loop. Header field
// continuation lines (starting with space/tab) are joined onto the previous
// field, keeping raw bytes (str2ck strips the embedded line endings anyway).
// The body is everything after the first empty line.
func splitHeadersBody(msg []byte) (fields [][]byte, body []byte) {
	i := 0
	for i < len(msg) {
		nl := bytes.IndexByte(msg[i:], '\n')
		var end int
		if nl < 0 {
			end = len(msg)
		} else {
			end = i + nl + 1
		}
		line := msg[i:end]

		if isBlankLine(line) {
			return fields, msg[end:]
		}
		if len(fields) > 0 && (line[0] == ' ' || line[0] == '\t') {
			last := len(fields) - 1
			fields[last] = append(fields[last], line...)
		} else {
			f := make([]byte, len(line))
			copy(f, line)
			fields = append(fields, f)
		}
		i = end
	}
	return fields, nil // no blank line: no body
}

// isBlankLine reports whether a physical line (terminator included) is empty,
// i.e. "\n" or "\r\n" — the header/body separator.
func isBlankLine(line []byte) bool {
	switch len(line) {
	case 0:
		return true
	case 1:
		return line[0] == '\n'
	case 2:
		return line[0] == '\r' && line[1] == '\n'
	}
	return false
}

// hasPrefixFold reports a case-insensitive prefix match (CLITCMP).
func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if toLower(b[i]) != toLower(prefix[i]) {
			return false
		}
	}
	return true
}

// Checksums computes the DCC checksums for a raw message, returning them in the
// type order dccproc -C prints (skipping ones that are not produced/valid).
// This is the offline debug path; it is the analogue of gazor.Signatures.
func Checksums(msg []byte) []Checksum {
	fields, body := splitHeadersBody(msg)

	var fromSum, msgIDSum *Sum
	for _, f := range fields {
		switch {
		case hasPrefixFold(f, "From:"):
			s := str2ck("", string(f[len("From:"):]))
			fromSum = &s
		case hasPrefixFold(f, "Message-ID:"):
			s := str2ck("", string(f[len("Message-ID:"):]))
			msgIDSum = &s
		}
	}
	// dccproc synthesises a checksum of "" when there is no Message-ID.
	msgIDPresent := msgIDSum != nil
	if msgIDSum == nil {
		s := str2ck("", "")
		msgIDSum = &s
	}

	// Body + fuzzy checksums.
	bodySum, bodyOK, fuz1Sum, fuz1OK, fuz2Sum, fuz2OK := computeBody(body)

	var out []Checksum
	add := func(t CkType, s Sum, report bool) {
		out = append(out, Checksum{Type: t, Label: t.label(), Sum: s, Report: report})
	}
	if fromSum != nil {
		add(CkFrom, *fromSum, true)
	}
	// A real Message-ID is reported; a synthesised empty one is not (rpt2srvr=0).
	add(CkMessageID, *msgIDSum, msgIDPresent)
	if bodyOK {
		add(CkBody, bodySum, true)
	}
	if fuz1OK {
		add(CkFuz1, fuz1Sum, true)
	}
	if fuz2OK {
		add(CkFuz2, fuz2Sum, true)
	}
	return out
}
