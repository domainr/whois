package whois

import (
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout for whois queries.
const DefaultTimeout = 10 * time.Second

var (
	tr = &http.Transport{
		Dial: dialTimeout,
		ResponseHeaderTimeout: DefaultTimeout,
	}
	client = &http.Client{Transport: tr}
)

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

// Resolve resolves a given request’s query. Will not re-resolve Host if already set.
func (req *Request) Resolve() error {
	if req.Host == "" {
		err := req.resolveHost()
		if err != nil {
			return err
		}
	}
	srv := req.Server()
	if srv.Resolve == nil {
		return nil
	}
	return srv.Resolve(req)
}

// resolveHost resolves a query to a whois host.
func (req *Request) resolveHost() error {
	var ok bool
	labels := strings.Split(req.Query, ".")
	for i := 0; i < len(labels) && !ok; i++ {
		req.Host, ok = zones[strings.Join(labels[i:], ".")]
	}
	if !ok {
		return errors.New("No whois server found for " + req.Query)
	}
	return nil
}

// Server returns a server implementation for a given host. It will always return a valid server.
func (req *Request) Server() *Server {
	srv, ok := servers[req.Host]
	if !ok {
		srv = defaultServer
	}
	return srv
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

func dialTimeout(network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: DefaultTimeout}
	return d.Dial(network, address)
}
