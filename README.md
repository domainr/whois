# go-whois

Go whois library

## Design Doc

```
func whois.Whois(query string) whois.Record             // fetches and returns a fully-parsed whois.Record

req = whois.Resolve(query)                              // returns a whois.Request
res = req.Perform()                                     // performs the request, returns a whois.Response
rec = res.Parse()                                       // parses the response, returns a whois.Record

whois.Response — intermediate record, raw response from a whois server for a given query
whois.Record — parsed whois response; structured data
```

### Logic

```
query := "domai.nr"
url := whois.Resolve(query)
response := whois.Fetch(url)
for response.Refer != "" {
  response = whois.Fetch(response.refer)
}

type Server struct {
  // URL (string template)
  // request body (string template)
}

var Servers map[string]Server
```
