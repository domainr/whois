package whois

const (
	// IANA is the default whois server for TLDs.
	IANA = "whois.iana.org"
)

// Request represents a whois request.
type Request struct {
	Query string
	Host  string
	URL   string
	Body  []byte
}

// NewRequest returns a prepared Request ready to fetch.
// On error, returns a nil Request and the error.
func NewRequest(query string) (*Request, error) {
	req := &Request{Query: query}
	if err := req.Prepare(); err != nil {
		return nil, err
	}
	return req, nil
}

// Prepare prepares a Request with an appropriate Adapter.
// First resolves whois server in req.Host if not already set.
// Returns any errors.
func (req *Request) Prepare() error {
	var err error
	if req.Host == "" {
		if req.Host, req.URL, err = Server(req.Query); err != nil {
			return err
		}
	}
	return req.Adapter().Prepare(req)
}

// Adapter returns an appropriate Adapter for the Request.
func (req *Request) Adapter() Adapter {
	return adapterFor(req.Host)
}
