package whois

import (
	"testing"

	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestReadMIME(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		// fmt.Printf("%s\n", fn)
		res, err := ReadMIMEFile(fn)
		st.Refute(t, res, nil)
		st.Assert(t, err, nil)
		// fmt.Printf("%#v\n\n", res)
	}
}

func TestPIRRateLimitText(t *testing.T) {
	req, err := NewRequest("google.org")
	st.Assert(t, err, nil)
	res, err := req.Fetch()
	st.Assert(t, err, nil)
	st.Expect(t, res.MediaType, "text/plain")
	st.Expect(t, res.Charset, "iso-8859-1")
	res.Body = []byte("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS\n")
	res.DetectContentType("")
	st.Expect(t, res.MediaType, "text/plain")
	st.Expect(t, res.Charset, "windows-1252")
	h := res.Header()
	st.Expect(t, h.Get("Content-Type"), "text/plain; charset=windows-1252")
}
