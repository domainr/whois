package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

const (
	timeout = 2000 * time.Millisecond
)

func Whois(query string) (string, error) {
	labels := strings.Split(query, ".")
	tld := labels[len(labels)-1]
	host := tld + ".whois-servers.net:43"
	c, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return "", err
	}

	c.SetDeadline(time.Now().Add(timeout))
	if _, err = fmt.Fprint(c, query, "\r\n"); err != nil {
		return "", err
	}

	buffer, err := ioutil.ReadAll(c)
	if err != nil {
		return "", err
	}

	return string(buffer[:]), nil
}
