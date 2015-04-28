package whois

import (
	"fmt"
)

type deAdapter struct {
	defaultAdapter
}

func (a *deAdapter) Prepare(req *Request) error {
	a.defaultAdapter.Prepare(req)
	req.Body = []byte(fmt.Sprintf("-T dn,ace %s\r\n", req.Query)) // http://www.denic.de/en/domains/whois-service.html
	return nil
}

func init() {
	BindAdapter(
		&deAdapter{},
		"whois.denic.de",
	)
}
