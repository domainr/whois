package whois

// Adapter contains server-specific code for retrieving and parsing whois data.
type Adapter interface {
	Prepare(*Request) error
}

var adapters = map[string]Adapter{}

// BindAdapter globally associates an Adapter with given hostname(s).
func BindAdapter(s Adapter, names ...string) {
	for _, name := range names {
		adapters[name] = s
	}
}

// AdapterFor returns an Adapter for the given host.
// If it cannot find a specific named Adapter, it will return a the default Adapter.
// AdapterFor will always return a valid Adapter.
func AdapterFor(host string) Adapter {
	if a, ok := adapters[host]; ok {
		return a
	}
	return adapters["default"]
}
