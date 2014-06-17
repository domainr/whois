package servers

import (
	"fmt"

	"github.com/domainr/go-whois/whois"
)

var de = &whois.Server{
	Resolve: func(req *whois.Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("-T dn,ace %s\r\n", req.Query)	// http://www.denic.de/en/domains/whois-service.html
		return nil
	},
}

func init() {
	whois.RegisterServer(
		de,
		"whois.denic.de",
	)
}
