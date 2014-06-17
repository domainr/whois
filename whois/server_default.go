package whois

import (
	"fmt"
)

var defaultServer = &Server{
	Resolve: func(req *Request) error {
		req.URL = ""
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}

func init() {
	register(
		defaultServer,
		"default",
	)
}
