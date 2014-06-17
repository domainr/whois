package servers

import (
	"fmt"

	"github.com/domainr/go-whois/whois"
)

var Default = &whois.Server{
	Resolve: func(req *whois.Request) error {
		req.URL = ""
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}

func init() {
	whois.RegisterServer(
		Default,
		"default",
	)
}
