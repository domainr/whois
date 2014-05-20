package types

// A Server retrieves and interprets whois results.
type Server struct {
	Resolve func(*Request) error
}
