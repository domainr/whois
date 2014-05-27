package whois

import (
	"net/url"
)

var az = &Server{
	Resolve: func(req *Request) error {
		values := url.Values{}
		values.Set("lang", "en")
		values.Set("domain", req.Query)
		values.Set("dom", "") // Server concatentates domain+dom, so we can leave dom empty
		req.URL = "http://www.whois.az/cgi-bin/whois.cgi"
		req.Body = values.Encode()
		return nil
	},
}

func init() {
	register(
		az,
		"www.whois.az",
		"www.nic.az",
	)
}
