package whois

import (
	"time"
)

// Request represents a specific type of whois request (HTTP, WHOIS, etc.)
type Request struct {
	Query string
	URL string
	Body []byte
}
