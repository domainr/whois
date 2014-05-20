package types

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

// DefaultTimeout for whois queries.
const DefaultTimeout = 10 * time.Second

// Request represents a whois request.
type Request struct {
	Query   string
	Host    string
	URL     string
	Body    string
	Timeout time.Duration
}

// NewRequest returns a request ready to fetch.
func NewRequest(q string) *Request {
	return &Request{Query: q, Timeout: DefaultTimeout}
}

// Fetch queries a whois server via whois protocol or by HTTP if URL is set.
func (r *Request) Fetch() (*Response, error) {
	if r.URL != "" {
		return r.fetchURL()
	}
	return r.fetchWhois()
}

func (r *Request) fetchWhois() (*Response, error) {
	resp := &Response{Request: r, FetchedAt: time.Now()}

	c, err := net.DialTimeout("tcp", r.Host+":43", r.Timeout)
	if err != nil {
		return resp, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(r.Timeout))
	if _, err = io.WriteString(c, r.Body); err != nil {
		return resp, err
	}
	if resp.Body, err = ioutil.ReadAll(c); err != nil {
		return resp, err
	}

	resp.ContentType = http.DetectContentType(resp.Body)

	return resp, nil
}

func (r *Request) fetchURL() (*Response, error) {
	resp := &Response{Request: r, FetchedAt: time.Now()}

	getResp, err := http.Get(r.URL)
	if err != nil {
		return resp, err
	}
	defer getResp.Body.Close()
	if resp.Body, err = ioutil.ReadAll(getResp.Body); err != nil {
		return resp, err
	}

	resp.ContentType = http.DetectContentType(resp.Body)

	return resp, nil
}
