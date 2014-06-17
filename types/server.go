package types

// RegisterServer globally associates a Server with given hostnames.
func RegisterServer(s *Server, names ...string) {
	for _, name := range names {
		servers[name] = s
	}
}

// A Server retrieves and interprets whois results.
type Server struct {
	Resolve func(*Request) error
}

var servers = map[string]*Server{}
