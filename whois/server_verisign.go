package whois

import (
	"fmt"
)

var verisign = &Server{
	Resolve: func(req *Request) error {
		defaultServer.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}

func init() {
	register(
		verisign,
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
