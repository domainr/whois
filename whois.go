package whois

// Whois queries a whois server for query and returns the result.
func Whois(query string) (string, error) {
	req, err := Resolve(query)
	if err != nil {
		return "", err
	}

	res, err := Fetch(req)
	if err != nil {
		return "", err
	}

	return string(res.Body), nil
}

// Fetch performs a whois Request.
func Fetch(req *Request) (*Response, error) {
	return DefaultClient.Fetch(req)
}
