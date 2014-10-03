package whois

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

const DefaultTimeout = 10 * time.Second

// Client represents a whois client. It contains internal state,
// including an http.Client, for executing whois Requests.
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// DefaultClient represents a shared whois client with a default
// timeout, HTTP transport, and dialer.
var DefaultClient = NewClient(DefaultTimeout)

// NewClient creates and initializes a new Client
func NewClient(timeout time.Duration) *Client {
	client := &Client{timeout: timeout}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		Dial:                  (client).Dial,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	client.httpClient = &http.Client{Transport: transport}
	return client
}

// Dial implements the Dial interface with the specified Client’s timeout.
// Client timeout affects cumulative dial + read time.
func (c *Client) Dial(network, address string) (net.Conn, error) {
	deadline := time.Now().Add(c.timeout)
	conn, err := net.DialTimeout(network, address, c.timeout)
	if err != nil {
		return conn, err
	}
	conn.SetDeadline(deadline)
	return conn, nil
}

// Fetch performs a Request.
func (c *Client) Fetch(req *Request) (*Response, error) {
	if req.URL != "" {
		return c.fetchHTTP(req)
	}
	return c.fetchWhois(req)
}

func (c *Client) fetchWhois(req *Request) (*Response, error) {
	conn, err := c.Dial("tcp", req.Host+":43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = io.WriteString(conn, req.Body); err != nil {
		return nil, err
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(conn); err != nil {
		return nil, err
	}
	res.DetectContentType("")
	return res, nil
}

func (c *Client) fetchHTTP(req *Request) (*Response, error) {
	hreq, err := httpRequest(req)
	if err != nil {
		return nil, err
	}
	hres, err := c.httpClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(hres.Body); err != nil {
		return nil, err
	}
	res.DetectContentType(hres.Header.Get("Content-Type"))
	return res, nil
}

func httpRequest(req *Request) (*http.Request, error) {
	var hreq *http.Request
	var err error
	// POST if non-zero Request.Body
	if len(req.Body) > 0 {
		hreq, err = http.NewRequest("POST", req.URL, strings.NewReader(req.Body))
	} else {
		hreq, err = http.NewRequest("GET", req.URL, nil)
	}
	if err != nil {
		return nil, err
	}
	// Some web whois servers require a Referer header
	hreq.Header.Add("Referer", req.URL)
	return hreq, nil
}
