package whois

// Status summarizes a domain name’s RPP or EPP status.
type Status int

// Availability statuses reported by whois records.
const (
	Unknown Status = iota
	Available
	Registered
	Reserved
	Invalid
)

// Record represents a parsed whois response.
type Record struct {
	Response
	Status
}
