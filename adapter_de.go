package whois

import (
	"fmt"
)

var de = &Adapter{
	Resolve: func(req *Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("-T dn,ace %s\r\n", req.Query)	// http://www.denic.de/en/domains/whois-service.html
		return nil
	},
}

func init() {
	RegisterAdapter(
		de,
		"whois.denic.de",
	)
}
