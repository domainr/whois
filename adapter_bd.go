package whois

import (
	"net/url"
	"strings"
)

var bd = &Adapter{
	Resolve: func(req *Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("dom", labels[0])
		values.Set("ext", labels[1])
		req.URL = "http://www.whois.com.bd/?" + values.Encode()
		req.Body = ""
		return nil
	},
}

func init() {
	RegisterAdapter(
		bd,
		"www.whois.com.bd",
	)
}
