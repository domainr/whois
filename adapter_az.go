package whois

import (
	"net/url"
)

var az = &Adapter{
	Resolve: func(req *Request) error {
		values := url.Values{}
		values.Set("lang", "en")
		values.Set("domain", req.Query)
		values.Set("dom", "") // Adapter concatentates domain+dom, so we can leave dom empty
		req.URL = "http://www.whois.az/cgi-bin/whois.cgi"
		req.Body = values.Encode()
		return nil
	},
}

func init() {
	RegisterAdapter(
		az,
		"www.whois.az",
		"www.nic.az",
	)
}
