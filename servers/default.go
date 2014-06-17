package servers

import (
	"fmt"

	"github.com/domainr/go-whois/core"
)

var Default = &core.Server{
	Resolve: func(req *core.Request) error {
		req.URL = ""
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}

func init() {
	core.RegisterServer(
		Default,
		"default",
	)
}
