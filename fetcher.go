package whois

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
	"time"
)

var Timeout = 3000 * time.Millisecond

func Fetch(u string) (*Response, error) {
	p, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	switch p.Scheme {
	case "whois":
		return fetchWhois(u)
	case "http":
		return fetchHTTP(u)
	case "https":
		return fetchHTTP(u)
	}

	return nil, errors.New("Unknown URL scheme: " + p.Scheme)
}

func fetchWhois(u string) (*Response, error) {
	response := &Response{URL: u, FetchedAt: time.Now()}

	p, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	host := p.Host
	if !strings.Contains(host, ":") {
		host = host + ":43"
	}
	query := p.Path[1:]

	c, err := net.DialTimeout("tcp", host, Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(Timeout))
	if _, err = fmt.Fprint(c, query, "\r\n"); err != nil {
		return nil, err
	}
	if response.Body, err = ioutil.ReadAll(c); err != nil {
		return nil, err
	}

	return response, nil
}

func fetchHTTP(u string) (*Response, error) {
	return &Response{}, nil
}
