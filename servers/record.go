package servers

// Status summarizes a domain name’s RPP or EPP status
type Status int

// Availability statuses reported by whois records.
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

// Returns true unless Status is Available.
func (r *Record) IsRegistered() bool {
	return r.Status != Available
}
