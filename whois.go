package whois

import (
	"errors"
	"net/url"
	"strings"

	"github.com/zonedb/zonedb"
)

// Whois queries a whois server for query and returns the result.
func Whois(query string) (string, error) {
	res, err := Fetch(query)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// Fetch queries a whois server and returns a Response.
func Fetch(query string) (*Response, error) {
	req, err := NewRequest(query)
	if err != nil {
		return nil, err
	}
	return req.Fetch()
}

// Resolve resolves query to an appropriate whois server.
// Returns an error if it cannot resolve query to any known host.
func Resolve(query string) (string, error) {
	// Queries on TLDs always against IANA
	if strings.Index(query, ".") < 0 {
		return IANA, nil
	}

	z := zonedb.PublicZone(query)
	if z == nil {
		return "", errors.New("No public zone found for " + query)
	}
	host := z.WhoisServer()
	if host != "" {
		return host, nil
	}
	u, err := url.Parse(z.WhoisURL())
	if err == nil {
		return u.Host, nil
	}
	return "", errors.New("No whois server found for " + query)
}
