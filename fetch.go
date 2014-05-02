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

var Timeout = 2000 * time.Millisecond

func Fetch(rawurl string) (*Response, error) {
	if u, err := url.Parse(rawurl); err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "whois":
		return fetchWhois(u)
	case "http":
		return fetchHTTP(u)
	case "https":
		return fetchHTTP(u)
	}

	return nil, errors.New("Unknown URL scheme: " + u.Scheme)
}

func fetchWhois(u url.URL) (*Response, error) {
	response = &Response{Query: query, FetchedAt: time.Now()}

	labels := strings.Split(query, ".")
	tld := labels[len(labels)-1]
	host := tld + ".whois-servers.net:43"

	if c, err := net.DialTimeout("tcp", host, Timeout); err != nil {
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
