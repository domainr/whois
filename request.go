package whois

import (
	"net/http"
	"io"
	"io/ioutil"
	"net"
	"time"
)

var Timeout = 10 * time.Second

// Request represents a whois request
type Request struct {
	Query   string
	Host    string
	URL     string
	Body    string
	Timeout time.Duration
}

func NewRequest(q string) *Request {
	return &Request{Query: q, Timeout: Timeout}
}

func (req *Request) Fetch() (*Response, error) {
	if req.URL != "" {
		return req.fetchURL()
	}
	return req.fetchWhois()
}

func (req *Request) fetchWhois() (*Response, error) {
	res := &Response{Request: req, FetchedAt: time.Now()}

	c, err := net.DialTimeout("tcp", req.Host+":43", req.Timeout)
	if err != nil {
		return res, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(req.Timeout))
	if _, err = io.WriteString(c, req.Body); err != nil {
		return res, err
	}
	if res.Body, err = ioutil.ReadAll(c); err != nil {
		return res, err
	}

	return res, nil
}

func (req *Request) fetchURL() (*Response, error) {
	res := &Response{Request: req, FetchedAt: time.Now()}
	
	hres, err := http.Get(req.URL)
	if err != nil {
		return res, err
	}
	defer hres.Body.Close()
	if res.Body, err = ioutil.ReadAll(hres.Body); err != nil {
		return res, err
	}
	
	return res, nil
}
