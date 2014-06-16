package whois

import (
	"mime"
	"net/http"
	"time"
)

// Response represents a whois response from a server.
type Response struct {
	Query     string
	Host      string
	FetchedAt time.Time
	MediaType string
	Charset   string
	Body      []byte
}

// NewResponse initializes a new whois response.
func NewResponse(query, host string) *Response {
	return &Response{
		Query:     query,
		Host:      host,
		FetchedAt: time.Now(),
	}
}

// String returns the response body.
func (res *Response) String() string {
	return string(res.Body)
}

// DetectContentType detects and sets the response content type and charset.
func (res *Response) DetectContentType(mt string) {
	// Sensible defaults
	res.MediaType = "text/plain"
	res.Charset = "utf-8"

	// Autodetect if not passed a Content-Type header
	if mt == "" {
		mt = http.DetectContentType(res.Body)
	}

	// Content type (e.g. text/plan or text/html)
	mt, params, err := mime.ParseMediaType(mt)
	if err != nil {
		return
	}
	res.MediaType = mt

	// Character set (e.g. utf-8)
	cs, ok := params["charset"]
	if !ok {
		return
	}
	res.Charset = cs
}

// Header returns a stringproto header representing the response.
func (res *Response) Header() http.Header {
	h := make(http.Header)
	h.Set("Query", res.Query)
	h.Set("Host", res.Host)
	h.Set("Fetched-At", res.FetchedAt.Format(time.RFC3339))
	h.Set("Content-Type", res.ContentType())
	return h
}

// ContentType returns an RFC 2045 compatible internet media type string.
func (res *Response) ContentType() string {
	return mime.FormatMediaType(res.MediaType, map[string]string{"charset": res.Charset})
}
