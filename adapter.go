package whois

// A Adapter retrieves and interprets whois results.
type Adapter struct {
	Resolve func(*Request) error
}

var adapters = map[string]*Adapter{}

// RegisterAdapter globally associates a Adapter with given hostnames.
func RegisterAdapter(s *Adapter, names ...string) {
	for _, name := range names {
		adapters[name] = s
	}
}
