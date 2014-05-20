package servers

import (
	"fmt"
	. "github.com/domainr/go-whois/types"
)

var Default = &Server{
	Resolve: func(req *Request) error {
		req.URL = ""
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}

func init() {
	register(
		Default,
		"default",
	)
}
