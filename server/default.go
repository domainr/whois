package server

import (
	"fmt"
)

var Default = Server{
	URL: func(h, q string) (string, error) {
		return fmt.Sprintf("whois://%s/%s", h, q), nil
	},
}
