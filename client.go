package whois

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

const (
	// DefaultTimeout sets the maximum lifetime of whois requests.
	DefaultTimeout = 30 * time.Second

	// DefaultReadLimit sets the maximum bytes a client will attempt to read from a connection.
	DefaultReadLimit = 1 << 20 // 1 MB
)

// Client represents a whois client. It contains an http.Client, for executing
// some whois Requests.
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// DefaultClient represents a shared whois client with a default timeout, HTTP
// transport, and dialer.
var DefaultClient = NewClient(DefaultTimeout)

// NewClient creates and initializes a new Client with the specified timeout.
func NewClient(timeout time.Duration) *Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	client := &Client{timeout: timeout}
	transport.Dial = client.Dial
	client.httpClient = &http.Client{Transport: transport}
	return client
}

// Dial implements the Dial interface, strictly enforcing that cumulative dial +
// read time is limited to timeout. It applies to both whois and HTTP connections.
func (c *Client) Dial(network, address string) (net.Conn, error) {
	deadline := time.Now().Add(c.timeout)
	conn, err := net.DialTimeout(network, address, c.timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	return conn, nil
}

// Fetch sends the Request to a whois server.
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
	if _, err = conn.Write(req.Body); err != nil {
		logError(err)
		return nil, err
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(io.LimitReader(conn, DefaultReadLimit)); err != nil {
		logError(err)
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
	if res.Body, err = ioutil.ReadAll(io.LimitReader(hres.Body, DefaultReadLimit)); err != nil {
		logError(err)
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
		hreq, err = http.NewRequest("POST", req.URL, bytes.NewReader(req.Body))
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

func logError(err error) {
	switch t := err.(type) {
	case syscall.Errno:
		fmt.Fprintf(os.Stderr, "syscall.Errno %d: %s\n", t, err.Error())
	case net.Error:
		fmt.Fprintf(os.Stderr, "net.Error timeout=%t, temp=%t: %s\n", t.Timeout(), t.Temporary(), err.Error())
	default:
		fmt.Fprintf(os.Stderr, "Unknown error %v: %s\n", t, err.Error())
	}
}
