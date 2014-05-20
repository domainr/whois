package servers

import (
	"net/url"
	"strings"
)

var cenpac = &Server{
	Resolve: func(req *Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("subdomain", labels[0])
		values.Set("tld", labels[1])
		// "http://cenpac.net.nr/dns/whois.html?subdomain=domai&tld=nr"
		req.URL = "http://cenpac.net.nr/dns/whois.html?" + values.Encode()
		req.Body = ""
		return nil
	},
}

func init() {
	register(
		cenpac,
		"cenpac.net.nr",
	)
}
