package whois

import (
	"fmt"
)

var Verisign = Server{
	Resolve: func(req *Request) error {
		Default.Resolve(req)
		req.Body = fmt.Sprintf("=%s\r\n", req.Query)
		return nil
	},
}
