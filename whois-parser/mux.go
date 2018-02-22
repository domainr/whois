package parser

// QueryType identify the type of
// WHOIS query for the parser
type QueryType int

// Types of WHOIS query
const (
	TypeTLD QueryType = iota
	TypeDomain
	TypeIPv4
	TypeIPv6
	TypeOther
)

// Mux stores the Parsers against the registrant hostname
// and can parse a given host, body pair.
type Mux map[string]Parser

// Set a Parser implementation for a given
// registrar / registry
func (m Mux) Set(host string, parser Parser) {
	m[host] = parser
}

// ParserOf returns the parser of the given query and host.
func (m Mux) ParserOf(host string, queryType QueryType) (parser Parser) {
	var ok bool
	if parser, ok = m[host]; ok {
		return
	}
	parser, _ = m[""] // use fallback parser, if any
	return
}

// DefaultMux returns a Mux with all default parser implementations
func DefaultMux() *Mux {
	defaultParser := CommonDomainRecordMapping()(ParseCommonDomainRecord)
	return &Mux{
		"":                       defaultParser,
		"whois.pir.org":          defaultParser,
		"whois.verisign-grs.com": defaultParser,
		"whois.cnnic.cn":         CNNICMapping()(ParseCNNICDomainRecord),
		"whois.denic.de":         DENICMapping()(ParseDENICDomainRecord),
	}
}
