package whois

import ()

// Status summarizes a domain name’s RPP or EPP status
type Status int

const (
	Available Status = iota
	Registered
	Invalid
)

// Record represents a parsed whois response
type Record struct {
	Response
	Status
}

func (record *Record) IsRegistered() bool {
	return record.Status != Available
}
