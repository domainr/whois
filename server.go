package whois

type Server struct {
	Resolve func(*Request) error
}

var servers = map[string]*Server{
	"default":                    &Default,
	"whois.verisign-grs.com":     &Verisign,
	"bzwhois.verisign-grs.com":   &Verisign,
	"ccwhois.verisign-grs.com":   &Verisign,
	"jobswhois.verisign-grs.com": &Verisign,
}
