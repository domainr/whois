package whois

import (
	"github.com/domainr/go-whois/types"
	_ "github.com/domainr/go-whois/servers"
)

// Whois queries a whois server for q and returns the result.
func Whois(q string) (string, error) {
	req, err := Resolve(q)
	if err != nil {
		return "", err
	}

	res, err := req.Fetch()
	if err != nil {
		return "", err
	}

	return string(res.Body), nil
}

// Resolve finds a whois server for q and prepares a Request.
func Resolve(q string) (*types.Request, error) {
	req := types.NewRequest(q)
	err := req.Resolve()
	return req, err
}
