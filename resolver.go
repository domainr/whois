package whois

import (
	"time"
)

func Resolve(query string) (*Request, error) {
	request = &Request{Query: query}
	return request, nil
}
