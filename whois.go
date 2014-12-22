package whois

//go:generate go run zones_generate.go

import (
	"errors"
	"strings"
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
	labels := strings.Split(query, ".")

	// Queries on TLDs always against IANA
	if len(labels) == 1 {
		return IANA, nil
	}

	// Otherwise, query zones map
	for i := 0; i < len(labels); i++ {
		if host, ok := zones[strings.Join(labels[i:], ".")]; ok {
			return host, nil
		}
	}

	return "", errors.New("No whois server found for " + query)
}
