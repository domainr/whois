package whois

import (
	"fmt"
)

// Verisign resolves whois requests for Verisign, Inc.
type Verisign struct{}

// Resolve queries verisign whois by prepending an equals sign to the domain name.
func (v *Verisign) Resolve(req *Request) error {
	new(Default).Resolve(req)
	req.Body = fmt.Sprintf("=%s\r\n", req.Query)
	return nil
}

func init() {
	register(
		&Verisign{},
		"whois.verisign-grs.com",
		"bzwhois.verisign-grs.com",
		"ccwhois.verisign-grs.com",
		"jobswhois.verisign-grs.com",
	)
}
