package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func Whois(query string) (string, error) {
	labels := strings.Split(query, ".")
	tld := labels[len(labels)-1]
	host := tld + ".whois-servers.net:43"
	c, err := net.Dial("tcp", host)
	if err != nil {
		return "", err
	}

	if _, err = fmt.Fprint(c, query, "\r\n"); err != nil {
		return "", err
	}

	buffer, err := ioutil.ReadAll(c)
	if err != nil {
		return "", err
	}

	return string(buffer[:]), nil
}

func Fetch(query string) (*Response, error) {
	if fetcher, err := selectAdapter(query); err != nil {
		return nil, err
	}
	return adapter.fetch(query)
}