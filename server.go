package whois

type Server struct {
	Resolve func(*Request) error
}

// Servers maps hostnames to Server implementations.
var Servers = map[string]*Server{}

func (server Server) register(names ...string) *Server {
	for _, name := range names {
		Servers[name] = &server
	}
	return &server
}
