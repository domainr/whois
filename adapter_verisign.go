package whois

import (
	"fmt"
)

type verisignAdapter struct {
	DefaultAdapter
}

func (a *verisignAdapter) Prepare(req *Request) error {
	a.DefaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("=%s\r\n", req.Query))
	return nil
}

func init() {
	BindAdapter(
		&verisignAdapter{},
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
