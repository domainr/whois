package whois

import (
	"fmt"
	"io/ioutil"
)

// Adapter contains server-specific code for retrieving and parsing whois data.
type Adapter interface {
	Prepare(*Request) error
	Text(*Response) ([]byte, error)
}

var adapters = map[string]Adapter{}

// BindAdapter globally associates an Adapter with given hostname(s).
func BindAdapter(s Adapter, names ...string) {
	for _, name := range names {
		adapters[name] = s
	}
}

// AdapterFor returns an Adapter for the given host.
// If it cannot find a specific named Adapter, it will return a the default Adapter.
// AdapterFor will always return a valid Adapter.
func AdapterFor(host string) Adapter {
	if a, ok := adapters[host]; ok {
		return a
	}
	return adapters["default"]
}

// DefaultAdapter represents the base Adapter for most whois servers.
type DefaultAdapter struct{}

// Resolve adapts a Request for a standard whois server.
func (a *DefaultAdapter) Prepare(req *Request) error {
	req.URL = ""
	req.Body = []byte(fmt.Sprintf("%s\r\n", req.Query))
	return nil
}

// Text returns the UTF-8 text content from the Response body.
func (a *DefaultAdapter) Text(res *Response) ([]byte, error) {
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

func init() {
	BindAdapter(
		&DefaultAdapter{},
		"default",
	)
}
