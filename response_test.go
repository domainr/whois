package whois

import (
	"io"
	"strings"
	"testing"

	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestResponse_Text(t *testing.T) {
	r := NewResponse("google.com", "whois.verisign-grs.com")
	r.Charset = "utf-8"
	r.Body = []byte("hello")
	text, err := r.Text()
	st.Expect(t, err, nil)
	st.Expect(t, string(text), "hello")
}

func TestResponse_String(t *testing.T) {
	r := NewResponse("google.com", "whois.verisign-grs.com")
	r.Charset = "utf-8"
	r.Body = []byte("hello")
	st.Expect(t, r.String(), "hello")
}

func TestReadMIME(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		// fmt.Printf("%s\n", fn)
		res, err := ReadMIMEFile(fn)
		st.Reject(t, res, nil)
		st.Expect(t, err, nil)
		// fmt.Printf("%#v\n\n", res)
	}
}

func TestReadMIMEEmpty(t *testing.T) {
	res, err := ReadMIME(strings.NewReader(""))
	st.Reject(t, res, nil)
	st.Expect(t, err, io.EOF)
}

func TestPIRRateLimitText(t *testing.T) {
	req, err := NewRequest("google.org")
	st.Assert(t, err, nil)
	res, err := DefaultClient.Fetch(req)
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
