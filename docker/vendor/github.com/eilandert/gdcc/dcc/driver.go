package dcc

// computeBody runs the body, Fuz1 and Fuz2 checksummers over the raw message
// body. For now this is the non-MIME ASCII fast path (ck_body.c with
// mime_nest == 0): the whole body streams straight through the decoders.
// MIME multipart / quoted-printable / base64 handling is layered in later.
func computeBody(body []byte) (bodySum Sum, bodyOK bool, fuz1Sum Sum, fuz1OK bool, fuz2Sum Sum, fuz2OK bool) {
	bs := newBodyState()
	f1 := newFuz1State()
	f2 := newFuz2State()

	// decode_sum for the ASCII text path feeds the same bytes to all three.
	bs.body0(body)
	f1.fuz1(body)
	f2.fuz2(body)

	// cks_fin flushes the fuzzy decoders with a trailing newline.
	f1.fuz1([]byte("\n"))
	f2.fuz2([]byte("\n"))

	bodySum, bodyOK = bs.final()
	fuz1Sum, fuz1OK = f1.final()
	fuz2Sum, fuz2OK = f2.final(&f1.url)
	return
}
