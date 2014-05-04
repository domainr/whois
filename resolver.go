package whois

import (
	"errors"
	"strings"
)

func Resolve(q string) (string, error) {
	labels := strings.Split(q, ".")
	zone := labels[len(labels)-1]
	h, ok := zones[zone]
	if !ok {
		return "", errors.New("No whois server found for " + q)
	}
	srv, ok := servers[h]
	if !ok {
		srv = servers["default"]
	}
	return srv.URL(h, q)
}
