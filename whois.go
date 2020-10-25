package whois

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/zonedb/zonedb"
)

// Fetch queries a whois server and returns a Response.
func Fetch(query string) (*Response, error) {
	req, err := NewRequest(query)
	if err != nil {
		return nil, err
	}
	return DefaultClient.Fetch(req)
}

// Server returns the whois server and optional URL for a given query.
// Returns an error if it cannot resolve query to any known host.
func Server(query string) (string, string, error) {
	// Queries on TLDs always against IANA
	if strings.Index(query, ".") < 0 {
		return IANA, "", nil
	}
	z := zonedb.PublicZone(query)
	if z == nil {
		return "", "", fmt.Errorf("no public zone found for %s", query)
	}

	// Try whois URL first (these are relatively rare)
	wu := z.WhoisURL()
	if wu != "" {
		u, err := url.Parse(wu)
		if err == nil && u.Host != "" {
			return u.Host, wu, nil
		}
	}

	// Then try host (more common)
	h := z.WhoisServer()
	if h != "" {
		return h, "", nil
	}

	return "", "", fmt.Errorf("no whois server found for %s", query)
}
