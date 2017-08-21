package whois

import (
	"net/url"
	"strings"
)

type bdAdapter struct {
	defaultAdapter
}

func (a *bdAdapter) Prepare(req *Request) error {
	labels := strings.SplitN(req.Query, ".", 2)
	values := url.Values{}
	values.Set("dom", labels[0])
	values.Set("ext", labels[1])
	req.URL = "http://www.whois.com.bd/?" + values.Encode()
	req.Body = nil // Always override existing request body
	return nil
}

func init() {
	BindAdapter(
		&bdAdapter{},
		"www.whois.com.bd",
	)
}
