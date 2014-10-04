package whois

import (
	"fmt"
)

type verisignAdapter struct {
	DefaultAdapter
}

func (a *verisignAdapter) Resolve(req *Request) error {
	a.DefaultAdapter.Resolve(req)
	req.Body = fmt.Sprintf("=%s\r\n", req.Query)
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
