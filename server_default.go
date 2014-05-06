package whois

import (
	"fmt"
)

var Default = Server{
	Resolve: func(req *Request) error {
		req.URL = fmt.Sprintf("whois://%s", req.Host)
		req.Body = fmt.Sprintf("%s\r\n", req.Query)
		return nil
	},
}
