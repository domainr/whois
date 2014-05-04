package whois

import (
	"github.com/domainr/go-whois/server"
)

var servers = map[string]*server.Server{
	"default":                    &server.Default,
	"whois.verisign-grs.com":     &server.Verisign,
	"bzwhois.verisign-grs.com":   &server.Verisign,
	"ccwhois.verisign-grs.com":   &server.Verisign,
	"jobswhois.verisign-grs.com": &server.Verisign,
}
