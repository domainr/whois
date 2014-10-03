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

// Resolve associates req with a Server capable of processing the request.
func (req *Request) Resolve() error {
	if err := req.resolveHost(); err != nil {
		return err
	}
	srv := req.Server()
	if srv.Resolve == nil {
		return errors.New("Server missing Resolve func")
	}
	if err := srv.Resolve(req); err != nil {
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

// Server returns a server implementation for a given host. It will always return a valid server.
func (req *Request) Server() *Server {
	srv, ok := servers[req.Host]
	if !ok {
		srv = servers["default"]
	}
	return srv
}

// Fetch performs a request.
func (req *Request) Fetch() (*Response, error) {
	return DefaultClient.Fetch(req)
}
