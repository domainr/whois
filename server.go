package whois

type Server struct {
	Resolve func(*Request) error
}
