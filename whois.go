package whois

// Whois queries a whois server for query and returns the result.
func Whois(query string) (string, error) {
	res, err := Fetch(query)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// Fetch queries a whois server and returns a Response.
func Fetch(query string) (*Response, error) {
	req, err := Resolve(query)
	if err != nil {
		return nil, err
	}
	return req.Fetch()
}
