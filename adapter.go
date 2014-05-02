package whois

type Adapter interface {
	Fetch(string) (*Response, error)
	Parse(*Response) (*Record, error)
}

func selectAdapter(query string) (Adapter, error) {
	return genericAdapter{}, nil
}
