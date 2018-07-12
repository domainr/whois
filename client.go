package whois

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
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
	Dial        func(string, string) (net.Conn, error)                  // Deprecated, use DialContext instead
	DialContext func(context.Context, string, string) (net.Conn, error) // Only used for port 43 (whois) requests, not HTTP(S)
	HTTPClient  *http.Client                                            // If nil, http.DefaultClient will be used
	Timeout     time.Duration                                           // Deprecated (use a Context instead)
}

// DefaultClient represents a shared whois client with a default timeout, HTTP
// transport, and dialer.
var DefaultClient = NewClient(DefaultTimeout)

// NewClient creates and initializes a new Client with the specified timeout.
func NewClient(timeout time.Duration) *Client {
	return &Client{
		Timeout: timeout,
	}
}

func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var conn net.Conn
	var err error
	switch {
	case c.DialContext != nil:
		conn, err = c.DialContext(ctx, network, address)
	case c.Dial != nil:
		conn, err = c.Dial(network, address)
	default:
		conn, err = defaultDialer.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		err = conn.SetDeadline(deadline)
	}
	return conn, err
}

var defaultDialer = &net.Dialer{}

// FetchError reports the underlying error and includes the target host of the fetch operation.
type FetchError struct {
	Err  error
	Host string
}

// Error implements the error interface.
func (f *FetchError) Error() string {
	return f.Err.Error()
}

// Fetch sends the Request to a whois server.
func (c *Client) Fetch(req *Request) (*Response, error) {
	return c.FetchContext(context.Background(), req)
}

// FetchContext sends the Request to a whois server.
// If ctx cancels or times out before the request completes, it will return an error.
func (c *Client) FetchContext(ctx context.Context, req *Request) (*Response, error) {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	if req.URL != "" {
		return c.fetchHTTP(ctx, req)
	}
	return c.fetchWhois(ctx, req)
}

func (c *Client) fetchWhois(ctx context.Context, req *Request) (*Response, error) {
	if req.Host == "" {
		return nil, &FetchError{fmt.Errorf("no request host for %s", req.Query), "unknown"}
	}
	conn, err := c.dialContext(ctx, "tcp", req.Host+":43")
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	defer conn.Close()
	if _, err = conn.Write(req.Body); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(io.LimitReader(conn, DefaultReadLimit)); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res.DetectContentType("")
	return res, nil
}

func (c *Client) fetchHTTP(ctx context.Context, req *Request) (*Response, error) {
	hreq, err := httpRequest(ctx, req)
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	hres, err := hc.Do(hreq)
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(io.LimitReader(hres.Body, DefaultReadLimit)); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res.DetectContentType(hres.Header.Get("Content-Type"))
	return res, nil
}

func httpRequest(ctx context.Context, req *Request) (*http.Request, error) {
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
	return hreq.WithContext(ctx), nil
}

func logError(err error) {
	switch t := err.(type) {
	case net.Error:
		fmt.Fprintf(os.Stderr, "net.Error timeout=%t, temp=%t: %s\n", t.Timeout(), t.Temporary(), err.Error())
	default:
		fmt.Fprintf(os.Stderr, "Unknown error %v: %s\n", t, err.Error())
	}
}
