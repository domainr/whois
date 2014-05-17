package whois

// Resolver is the interface all whois resolvers must satisfy.
type Resolver interface {
	Resolve(*Request) error
}

// Resolvers holds the set of registered whois resolvers.
var Resolvers = make(map[string]Resolver)

// Each whois resolver must register itself with package whois in the init function.
func register(r Resolver, names ...string) {
	for _, name := range names {
		Resolvers[name] = r
	}
}
