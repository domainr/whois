package servers

import (
	"fmt"
	"github.com/domainr/go-whois/core"
)

var verisign = &core.Server{
	Resolve: func(req *core.Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}

func init() {
	core.RegisterServer(
		verisign,
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
