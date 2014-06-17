package servers

import (
	"net/url"
	"strings"

	"github.com/domainr/go-whois/whois"
)

var bd = &whois.Server{
	Resolve: func(req *whois.Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("dom", labels[0])
		values.Set("ext", labels[1])
		req.URL = "http://www.whois.com.bd/?" + values.Encode()
		req.Body = ""
		return nil
	},
}

func init() {
	whois.RegisterServer(
		bd,
		"www.whois.com.bd",
	)
}
