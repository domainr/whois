package servers

import (
	. "github.com/domainr/go-whois/types"
)

// Servers maps hostnames to Server implementations.
var Servers = map[string]*Server{}

func register(s *Server, names ...string) {
	for _, name := range names {
		Servers[name] = s
	}
}
