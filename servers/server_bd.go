package servers

import (
	"net/url"
	"strings"

	"github.com/domainr/go-whois/types"
)

var bd = &types.Server{
	Resolve: func(req *types.Request) error {
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
	types.RegisterServer(
		bd,
		"www.whois.com.bd",
	)
}
