package servers

import (
	"net/url"
	"strings"

	"github.com/domainr/go-whois/types"
)

var nr = &types.Server{
	Resolve: func(req *types.Request) error {
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
	types.RegisterServer(
		nr,
		"cenpac.net.nr",
	)
}
