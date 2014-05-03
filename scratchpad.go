// +build ignore

package whois

import (
	"strings"
)

/*

Servers:

- mutate query into a request (URL?)
- fetch response from server <- should they?
	- should fetch check CNAME? — NO. whois-servers.net not comprehensive
	- should resolve check CNAME? - NO. IANA more comprehensive
- parse response

*/

var verisign = {
	url: "whois://whois.verisign-grs.com/={{query}}",
}

var cenpac = {
	fetch: func(query string) {
		url := strings.SplitN(query, ".", 2)
	}
}

var request = Request{
	Query: query,
	QueryNormalized: queryNormalized,
	Zone: "nr",
	URL: "http://cenpac.net.nr/dns/whois.html?subdomain=domai&tld=nr",
	Body: "",
}

// Generic adapter, obtains CNAME for TLD.whois-servers.net
// whois-servers.net not comprehensive! (missing gay, computers, etc)
var generic = {
	resolve: func(query) {
		labels := strings.Split(query, ".")
		host := fmt.Sprintf("%s.whois-servers.net", labels[-1])
		cname := queryDNS(host)
		if _, ok := servers[cname]; ok {
			return servers[cname].resolve(query)
		}
	}
}

