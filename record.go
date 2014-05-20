package whois

// Status summarizes a domain name’s RPP or EPP status.
type Status int

// Availability statuses reported by whois records.
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

// Returns whether a domain is registered.
func (r *Record) IsRegistered() bool {
	return r.Status != Available
}
