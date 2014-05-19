package whois

import (
	"fmt"
)

// Default is a whois request that sends the domain name followed by CRLF.
type Default struct{}

func (d *Default) Resolve(req *Request) error {
	req.URL = ""
	req.Body = fmt.Sprintf("%s\r\n", req.Query)
	return nil
}

// Don't register Default, just use an instance of it where needed.
