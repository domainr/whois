package whois

import (
	"fmt"
)

var de = &Server{
	Resolve: func(req *Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("-T dn,ace %s\r\n", req.Query)	// http://www.denic.de/en/domains/whois-service.html
		return nil
	},
}

func init() {
	RegisterServer(
		de,
		"whois.denic.de",
	)
}
