package whois

import (
	"errors"
	"strings"
)

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

func Resolve(q string) (*Request, error) {
	req := NewRequest(q)

	labels := strings.Split(q, ".")
	zone := labels[len(labels)-1]

	req.Host = zones[zone]
	if req.Host == "" {
		return req, errors.New("No whois server found for " + q)
	}

	var srv Resolver
	if srv = Resolvers[req.Host]; srv == nil {
		srv = &Default{}
	}
	srv.Resolve(req)

	return req, nil
}
