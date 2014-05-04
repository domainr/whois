package whois

import (
	"errors"
	"fmt"
	"strings"
)

func Resolve(query string) (string, error) {
	labels := strings.Split(query, ".")
	zone := labels[len(labels)-1]
	server, ok := zones[zone]
	if !ok {
		return "", errors.New("No whois server found for " + query)
	}
	u := fmt.Sprintf("whois://%s/%s", server, query)
	return u, nil
}
