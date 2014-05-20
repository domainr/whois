package whois

// Status summarizes a domain name’s RPP or EPP status.
type Status int

const (
	Unknown Status = iota
	Available
	Registered
	Invalid
)

// Record represents a parsed whois response.
type Record struct {
	Response
	Status
}

func (r *Record) IsRegistered() bool {
	return r.Status != Available
}
