package whois

// A Server retrieves and interprets whois results.
type Server struct {
	Resolve func(*Request) error
}

var servers = map[string]*Server{}

func register(s *Server, names ...string) {
	for _, name := range names {
		servers[name] = s
	}
}
