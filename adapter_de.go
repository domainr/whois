package whois

import (
	"fmt"
)

type deAdapter struct {
	DefaultAdapter
}

func (a *deAdapter) Resolve(req *Request) error {
	a.DefaultAdapter.Resolve(req)
	req.Body = fmt.Sprintf("-T dn,ace %s\r\n", req.Query) // http://www.denic.de/en/domains/whois-service.html
	return nil
}

func init() {
	BindAdapter(
		&deAdapter{},
		"whois.denic.de",
	)
}
