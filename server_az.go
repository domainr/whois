package whois

import (
	"net/url"
	"strings"
)

var az = &Server{
	Resolve: func(req *Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("lang", "en")
		values.Set("domain", labels[0])
		values.Set("dom", labels[1])
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
