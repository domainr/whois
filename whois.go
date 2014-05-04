package whois

func Whois(q string) (string, error) {
	u, err := Resolve(q)
	if err != nil {
		return "", err
	}

	res, err := Fetch(u)
	if err != nil {
		return "", err
	}

	return string(res.Body), nil
}
