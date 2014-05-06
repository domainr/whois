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

// Request represents a whois request
type Request struct {
	Query   string
	Host    string
	URL     string
	Body    string
	Timeout time.Duration
}

func (req *Request) Fetch() (*Response, error) {
	p, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}

	switch p.Scheme {
	case "whois":
		return req.fetchWhois()
	case "http":
	case "https":
		return req.fetchHTTP()
	}

	return nil, errors.New("Unknown URL scheme: " + p.Scheme)
}

func (req *Request) fetchWhois() (*Response, error) {
	response := &Response{Request: req, FetchedAt: time.Now()}

	p, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}

	host := p.Host
	if !strings.Contains(host, ":") {
		host = host + ":43"
	}

	c, err := net.DialTimeout("tcp", host, req.Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(req.Timeout))
	if _, err = fmt.Print(c, req.Body); err != nil {
		return nil, err
	}
	if response.Body, err = ioutil.ReadAll(c); err != nil {
		return nil, err
	}

	return response, nil
}

func (req *Request) fetchHTTP() (*Response, error) {
	return &Response{}, nil
}
