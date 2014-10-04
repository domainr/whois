package whois

import (
	"errors"
	"strings"
)

const (
	IANA = "whois.iana.org"
)

// Request represents a whois request.
type Request struct {
	Query string
	Host  string
	URL   string
	Body  string
}

// Resolve returns a Request ready to fetch.
func Resolve(query string) (*Request, error) {
	req := &Request{Query: query}
	if err := req.Resolve(); err != nil {
		return nil, err
	}
	return req, nil
}

// Resolve identifies an Adapter capable of processing the Request.
func (req *Request) Resolve() error {
	if err := req.resolveHost(); err != nil {
		return err
	}
	a := req.Adapter()
	if err := a.Resolve(req); err != nil {
		return err
	}
	return nil
}

// resolveHost resolves a query to a whois host.
func (req *Request) resolveHost() error {
	labels := strings.Split(req.Query, ".")

	// Queries on TLDs always against IANA
	if len(labels) == 1 {
		req.Host = IANA
		return nil
	}

	// Otherwise, query zones map
	var ok bool
	for i := 0; i < len(labels) && !ok; i++ {
		req.Host, ok = zones[strings.Join(labels[i:], ".")]
	}
	if !ok {
		return errors.New("No whois server found for " + req.Query)
	}
	return nil
}

// Adapter returns an adapter for a given host. It will always return a valid adapter.
func (req *Request) Adapter() Adapter {
	if a, ok := adapters[req.Host]; ok {
		return a
	}
	return adapters["default"]
}

// Fetch performs a request.
func (req *Request) Fetch() (*Response, error) {
	return DefaultClient.Fetch(req)
}
