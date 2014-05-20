package whois

import (
	"time"
)

// Response represents a whois response from a server.
type Response struct {
	*Request
	FetchedAt   time.Time
	ContentType string
	Encoding    string
	Body        []byte
}

// String returns the response body.
func (res *Response) String() string {
	return string(res.Body)
}
