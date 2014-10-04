package whois

import (
	"fmt"
)

// DefaultAdapter represents the base Adapter for most whois servers.
type DefaultAdapter struct{}

// Resolve adapts a Request for a standard whois server.
func (a *DefaultAdapter) Prepare(req *Request) error {
	req.URL = ""
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

func init() {
	BindAdapter(
		&DefaultAdapter{},
		"default",
	)
}
