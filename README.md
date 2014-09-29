# Whois client for Go (golang)

`go get github.com/domainr/whois`

Go whois library, heavily inspired by [Ruby Whois](https://github.com/weppos/whois). WIP.

## Design Doc

```
func whois.Whois(query string) whois.Record   // fetches and returns a fully-parsed whois.Record

request = whois.Resolve(query)                // returns a whois.Request
response = req.Fetch()                        // fetches the request, returns a whois.Response
record = res.Parse()                          // parses the response, returns a whois.Record

whois.Request — represents a qualified whois request, including server, URL, and request body
whois.Response — intermediate record, raw response from a whois server for a given query
whois.Record — parsed whois response; structured data
```

### Logic

```
query := "domai.nr"
request := whois.Resolve(query)
response := request.Fetch()
record := response.Parse()
for record.Refer != "" {
  response = record.FetchRefer()
}
```

### TODO

- [ ] Create whois.Client
- [ ] Embed an http.Client in whois.Client to reuse state
- [ ] Implementations for known HTTP-based whois servers
- [ ] Parsers
