package whois

import (
	"strings"
	"time"
)

const (
	CRLF    = "\r\n"
	timeout = 2000 * time.Millisecond
)

func Whois(query string) (Record, error) {
	labels := strings.Split(query, ".")

	// FIXME: use TLD suffix database, if that would be more correct
	tld := labels[len(labels)-1]

	// Ref for determining hostname http://en.wikipedia.org/wiki/Whois
	host := tld + ".whois-servers.net:43"

	rec := Record{Response: Response{Query: query, URL: host}}

	return rec, rec.Fetch()
}

//type Fetcher func(string) (*Record, error)

// func Fetch(query string) (*Record, error) {
// 	fetcher = selectFetcher(query)
// 	return fetcher()
// }
