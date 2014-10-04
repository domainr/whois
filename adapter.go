package whois

// Adapter contains server-specific code for retrieving and parsing whois data.
type Adapter interface {
	Resolve(*Request) error
}

var adapters = map[string]Adapter{}

// BindAdapter globally associates an Adapter with given hostname(s).
func BindAdapter(s Adapter, names ...string) {
	for _, name := range names {
		adapters[name] = s
	}
}
