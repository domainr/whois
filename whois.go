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
	addr := tld + ".whois-servers.net:43"
	c, err := net.Dial("tcp", addr)
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
