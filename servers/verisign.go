package servers

import (
	"fmt"
	"github.com/domainr/go-whois/types"
)

var verisign = &types.Server{
	Resolve: func(req *types.Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}

func init() {
	types.RegisterServer(
		verisign,
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
