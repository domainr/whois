package servers

import (
	"net/url"
	"strings"

	"github.com/domainr/go-whois/core"
)

var nr = &core.Server{
	Resolve: func(req *core.Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("subdomain", labels[0])
		values.Set("tld", labels[1])
		req.URL = "http://cenpac.net.nr/dns/whois.html?" + values.Encode()
		req.Body = ""
		return nil
	},
}

func init() {
	core.RegisterServer(
		nr,
		"cenpac.net.nr",
	)
}
