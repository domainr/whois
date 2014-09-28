package whois

import (
	"fmt"
)

var verisign = &Server{
	Resolve: func(req *Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}

func init() {
	RegisterServer(
		verisign,
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
