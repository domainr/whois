package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"time"
)

// Status summarizes a domain name’s RPP or EPP status
type Status int

const (
	Unknown Status = iota
	Available
	Registered
	Invalid
)

// Record represents a parsed whois response
type Record struct {
	Response
	Status
}

func (r *Record) IsRegistered() bool {
	return r.Status != Available
}

func (r Record) String() string {
	if r.Response.Body == nil {
		return "<empty response>"
	} else {
		return r.Response.String()
	}
}

func (r *Record) Fetch() error {
	c, err := net.DialTimeout("tcp", r.URL, timeout)
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(timeout)) // Possibly redundant?
	if _, err = fmt.Fprint(c, r.Query, CRLF); err != nil {
		return err
	}
	r.Body, err = ioutil.ReadAll(c)
	if err != nil {
		return err
	}
	r.FetchedAt = time.Now()
	return nil
}
