# go-whois

Go whois library

## Design Doc

func whois.Whois(query string) whois.Record             // fetches and returns a fully-parsed whois.Record

func whois.Resolve(query string) whois.Request          // returns a whois Request, suitable for Fetch
func whois.Fetch(url string) whois.Response             // accepts a URL, returns a Response struct
func whois.Parse(response whois.Response) whois.Record  // parses a Response struct, returns a parsed Record

whois.Response — intermediate record, raw response from a whois server for a given query
whois.Record — parsed whois response; structured data

### Logic

query := "domai.nr"
server := whois.Resolve(query)
response := whois.Fetch(server, query)
for response.Refer != "" {
  response = whois.Fetch(response.refer, query)
}

type Server struct {
  // URL (string template)
  // request body (string template)
}

var Servers map[string]Server