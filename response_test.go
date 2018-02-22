package whois_test

import (
	"testing"

	"github.com/domainr/whois"
	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestResponse_Text(t *testing.T) {
	r := whois.NewResponse("google.com", "whois.verisign-grs.com")
	r.Charset = "utf-8"
	r.Body = []byte("hello")
	text, err := r.Text()
	st.Expect(t, err, nil)
	st.Expect(t, string(text), "hello")
}

func TestResponse_String(t *testing.T) {
	r := whois.NewResponse("google.com", "whois.verisign-grs.com")
	r.Charset = "utf-8"
	r.Body = []byte("hello")
	st.Expect(t, r.String(), "hello")
}

func TestReadMIME(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		// fmt.Printf("%s\n", fn)
		res, err := whois.ReadMIMEFile(fn)
		st.Reject(t, res, nil)
		st.Expect(t, err, nil)
		// fmt.Printf("%#v\n\n", res)
	}
}

func TestPIRRateLimitText(t *testing.T) {
	req, err := whois.NewRequest("google.org")
	st.Assert(t, err, nil)
	res, err := whois.DefaultClient.Fetch(req)
	st.Assert(t, err, nil)
	st.Expect(t, res.MediaType, "text/plain")
	st.Expect(t, res.Charset, "windows-1252")
	res.Body = []byte("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS\n")
	res.DetectContentType("")
	st.Expect(t, res.MediaType, "text/plain")
	st.Expect(t, res.Charset, "windows-1252")
	h := res.Header()
	st.Expect(t, h.Get("Content-Type"), "text/plain; charset=windows-1252")
}

func TestResponse_Parse(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		res, err := whois.ReadMIMEFile(fn)
		st.Refute(t, res, nil)
		st.Assert(t, err, nil)
		if res.MediaType != "text/plain" {
			continue
		}

		// basic information
		t.Logf("File:  %s", fn)
		t.Logf("Query: %s", res.Query)
		t.Logf("Host:  %s", res.Host)

		// test parsing
		rec, err := res.Parse()
		if err != nil {
			t.Logf("[Not Handled] parse error: %s", err.Error())
			t.Logf("\n")
			continue
		}

		// show parse record
		t.Logf("Record: %#v", rec)
		t.Logf("\n")
	}
}
