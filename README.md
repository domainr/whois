# Whois

[![GoDoc](http://img.shields.io/badge/docs-GoDoc-blue.svg)](https://godoc.org/github.com/domainr/whois)

`go get github.com/domainr/whois`

Whois client for Go (golang), inspired by [Ruby Whois](https://github.com/weppos/whois). Currently in production use at [Domainr](https://domainr.com).

## Design

```go
func whois.Whois(query string) *whois.Record  // Fetches and returns a fully-parsed whois.Record

request = whois.NewRequest(query)             // Returns a prepared whois.Request
response = whois.DefaultClient.Fetch(request) // Fetches the request, returns a whois.Response
record = response.Parse()                     // (not implemented yet) Parses the response, returns a whois.Record

whois.Request  // represents a qualified whois request, including server, URL, and request body
whois.Response // intermediate record, raw response from a whois server for a given query
whois.Record   // parsed whois response; structured data
```

### Logic

```go
query := "domai.nr"
request, err := whois.NewRequest(query)
response, err := whois.DefaultClient.Fetch(request)
record, err := response.Parse() // not implemented yet
if record.Refer != "" {
  response = whois.FetchRefer(record)
}
```

### TODO

- [X] Create whois.Client
- [X] Embed an http.Client in whois.Client to reuse state
- [ ] Implementations for known HTTP-based whois servers
- [ ] Parsers

## Credits

This code is made available under an MIT license. See LICENSE for more information.

© nb.io, LLC
