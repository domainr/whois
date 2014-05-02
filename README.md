# go-whois

Go whois library

## Design Doc

func whois.Whois(query string) whois.Record             // fetches and returns a fully-parsed whois.Record

func whois.Resolve(query string) whois.Request          // returns a whois Request, suitable for Fetch
func whois.Fetch(url string) whois.Response             // accepts a URL, returns a Response struct
func whois.Parse(response whois.Response) whois.Record  // parses a Response struct, returns a parsed Record

whois.Response — intermediate record, raw response from a whois server for a given query
whois.Record — parsed whois response; structured data
