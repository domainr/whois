package whois

import (
	"fmt"
)

type nameAdapter struct {
	defaultAdapter
}

func (a *nameAdapter) Prepare(req *Request) error {
	a.defaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("=%s\r\n", req.Query))
	return nil
}

func init() {
	BindAdapter(
		&nameAdapter{},
		"whois.nic.name",
	)
}
