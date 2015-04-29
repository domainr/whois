package whois

import (
	"fmt"
	"io/ioutil"
)

// Adapter contains server-specific code for retrieving and parsing whois data.
type Adapter interface {
	// Prepare performs any server-specific modifications of the Request.
	Prepare(*Request) error

	// Text returns the UTF-8 text of the Response body, stripping off any
	// excess data, (e.g. HTML) from a web response.
	Text(*Response) ([]byte, error)
}

// DefaultAdapter is the default Adapter for most whois servers.
var DefaultAdapter = &defaultAdapter{}

// defaultAdapter represents the base Adapter type.
type defaultAdapter struct{}

// Resolve adapts a Request for a standard whois server.
func (a *defaultAdapter) Prepare(req *Request) error {
	req.URL = ""
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

// Text returns the UTF-8 text content from the Response body.
func (a *defaultAdapter) Text(res *Response) ([]byte, error) {
	r, err := res.Reader()
	if err != nil {
		return nil, err
	}
	text, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return text, nil
}

// adapters holds a global list of bound Adapters.
var adapters = map[string]Adapter{}

// BindAdapter globally associates an Adapter with given hostname(s).
func BindAdapter(s Adapter, names ...string) {
	for _, name := range names {
		adapters[name] = s
	}
}

// adapterFor returns an Adapter for the given host.
// If it cannot find a specific named Adapter, it will return a the default Adapter.
// It will always return a valid Adapter.
func adapterFor(host string) Adapter {
	if a, ok := adapters[host]; ok {
		return a
	}
	return DefaultAdapter
}
