package server

import (
	"fmt"
)

var Verisign = Server{
	URL: func(h, q string) (string, error) {
		return fmt.Sprintf("whois://%s/=%s", h, q), nil
	},
}
