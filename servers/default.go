package servers

import (
	"fmt"

	"github.com/domainr/go-whois/types"
)

var Default = &types.Server{
	Resolve: func(req *types.Request) error {
		req.URL = ""
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}

func init() {
	types.RegisterServer(
		Default,
		"default",
	)
}
