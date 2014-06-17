package servers

import (
	"fmt"

	"github.com/domainr/go-whois/whois"
)

var verisign = &whois.Server{
	Resolve: func(req *whois.Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}

func init() {
	whois.RegisterServer(
		verisign,
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
