package whois_test

import (
	"fmt"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/domainr/whois"
	parser "github.com/domainr/whois/whois-parser"
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
	var fn string
	var res *whois.Response

	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	errTpl := "\n== Record not handled ==\nFile:\t%s\nQuery:\t%s\nHost:\t%s\nError:\t%s"

	defer func() {
		if r := recover(); r != nil {
			t.Errorf(
				errTpl,
				fn,
				res.Query,
				res.Host,
				fmt.Sprintf("%#v\n%s", r, debug.Stack()),
			)
		}
	}()

	for _, fn = range fns {
		res, err = whois.ReadMIMEFile(fn)
		st.Refute(t, res, nil)
		st.Assert(t, err, nil)
		if res.MediaType != "text/plain" {
			continue
		}

		// test if records are parsing without error
		rec, err := res.Parse()
		if err != nil {

			switch err {
			case parser.ErrorDomainNotFound:
				fallthrough
			case parser.ErrorDomainReserved:
				// do nothing
			default:
				t.Errorf(
					errTpl,
					fn,
					res.Query,
					res.Host,
					err.Error(),
				)
			}
			continue
		}

		// checks for TypeDomain record
		if rec.Type == parser.TypeDomain {
			if rec.DomainRecord == nil {
				t.Errorf(
					errTpl,
					fn,
					res.Query,
					res.Host,
					"rec.DomainRecord is nil",
				)
				continue
			}

			errs := make([]string, 0, 10)

			// Check Domain Name
			if have, want := strings.ToLower(rec.DomainRecord.DomainName), strings.ToLower(res.Query); want != have {
				errs = append(
					errs,
					fmt.Sprintf("rec.DomainRecord.DomainName is wrong. expected: %#v, got: %#v.", want, have),
				)
			}

			// Check Registry Domain ID
			if res.Host == "whois.denic.de" {
				// do nothing
			} else if have := rec.DomainRecord.RegistryID; have == "" {
				errs = append(
					errs,
					"rec.DomainRecord.RegistryID is empty.",
				)
			}

			// if there is any parse error
			if len(errs) != 0 {
				t.Errorf(
					errTpl,
					fn,
					res.Query,
					res.Host,
					strings.Join(errs, "\n\t"),
				)
				t.Logf("Domain Name: %#v", rec.Values.Get("Domain Name"))
				t.Logf("raw:\n%s", res.Body)
				return
			}
		}
	}
}
