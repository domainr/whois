package whois

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/andybalholm/cascadia"

	"github.com/PuerkitoBio/goquery"
)

type nrAdapter struct {
	defaultAdapter
}

func (a *nrAdapter) Prepare(req *Request) error {
	labels := strings.SplitN(req.Query, ".", 2)
	values := url.Values{}
	values.Set("subdomain", labels[0])
	values.Set("tld", labels[1])
	req.URL = "http://www.cenpac.net.nr/dns/whois.html?" + values.Encode()
	req.Body = nil // Always override existing request body
	return nil
}

var nrSelectTR = cascadia.MustCompile("hr+table tr:not(:has(tr))")

func (a *nrAdapter) Text(res *Response) ([]byte, error) {
	html, err := a.defaultAdapter.Text(res)
	if err != nil {
		return nil, err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(html))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	rows := doc.FindMatcher(nrSelectTR)
	rows.Each(func(i int, s *goquery.Selection) {
		buf.WriteString(s.Text())
		buf.WriteString("\n")
	})
	return buf.Bytes(), nil
}

func init() {
	BindAdapter(
		&nrAdapter{},
		"cenpac.net.nr",
		"www.cenpac.net.nr",
	)
}
