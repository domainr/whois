package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)
	
type genericAdapter struct{}

const (
	timeout = 2000 * time.Millisecond
)

func (adapter *genericAdapter) Fetch(query string) (*Response, error) {
	response = &Response{ Query: query, FetchedAt: time.Now()}
	
	labels := strings.Split(query, ".")
	tld := labels[len(labels)-1]
	host := tld + ".whois-servers.net:43"

	if c, err := net.DialTimeout("tcp", host, timeout); err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err = fmt.Fprint(c, query, "\r\n"); err != nil {
		return nil, err
	}
	if response.Body, err = ioutil.ReadAll(c); err != nil {
		return nil, err
	}

	return response, nil
}

func (adapter *genericAdapter) Parse(response *Response) (*Record, error) {

}
