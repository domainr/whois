package whois

import (
)

func Whois(query string) (string, error) {
	u, err := Resolve(query)
	if err != nil {
		return "", err
	}

	res, err := Fetch(u)
	if err != nil {
		return "", err
	}

	return string(res.Body), nil
}
