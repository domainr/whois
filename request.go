package whois

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
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
func (req *Request) Fetch() (*Response, error) {
	if req.URL != "" {
		return req.fetchURL()
	}
	return req.fetchWhois()
}

func (req *Request) fetchWhois() (*Response, error) {
	res := NewResponse(req.Query, req.Host)

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

	res.DetectContentType("")

	return res, nil
}

func (req *Request) fetchURL() (*Response, error) {
	res := NewResponse(req.Query, req.Host)

	var hreq *http.Request
	var err error
	if req.Body != "" {
		hreq, err = http.NewRequest("POST", req.URL, strings.NewReader(req.Body))
	} else {
		hreq, err = http.NewRequest("GET", req.URL, nil)
	}
	if err != nil {
		return res, err
	}
	hreq.Header.Add("Referer", req.URL)

	client := &http.Client{}
	hres, err := client.Do(hreq)
	if err != nil {
		return res, err
	}
	defer hres.Body.Close()
	if res.Body, err = ioutil.ReadAll(hres.Body); err != nil {
		return res, err
	}

	res.DetectContentType(hres.Header.Get("Content-Type"))

	return res, nil
}
