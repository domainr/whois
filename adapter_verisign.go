package whois

import (
	"fmt"
)

type verisignAdapter struct {
	defaultAdapter
}

func (a *verisignAdapter) Prepare(req *Request) error {
	a.defaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("=%s\r\n", req.Query))
	return nil
}

func init() {
	BindAdapter(
		&verisignAdapter{},
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"tvwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
