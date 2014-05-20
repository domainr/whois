package whois

import (
	"errors"
	"strings"

	"github.com/domainr/go-whois/servers"
)

// Whois queries the correct whois server for q and returns the whois result.
func Whois(q string) (string, error) {
	req, err := Resolve(q)
	if err != nil {
		return "", err
	}

	res, err := req.Fetch()
	if err != nil {
		return "", err
	}

	return string(res.Body), nil
}

// Resolve finds a registered whois server for q and prepares a request to be
// fetched from it.
func Resolve(q string) (*servers.Request, error) {
	req := servers.NewRequest(q)

	labels := strings.Split(q, ".")
	zone := labels[len(labels)-1]

	req.Host = Zones[zone]
	if req.Host == "" {
		return req, errors.New("No whois server found for " + q)
	}

	srv, ok := servers.Servers[req.Host]
	if !ok {
		srv = servers.Default
	}
	srv.Resolve(req)

	return req, nil
}
