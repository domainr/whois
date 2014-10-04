package whois

import (
	"fmt"
	"testing"

	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestScanner(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		res, err := readMIMEFile(fn)
		st.Refute(t, res, nil)
		st.Assert(t, err, nil)
		if res.MediaType != "text/plain" {
			continue
		}
		
		fmt.Printf("File:  %s\n", fn)
		fmt.Printf("Query: %s\n", res.Query)
		fmt.Printf("Host:  %s\n", res.Host)
		fmt.Printf("\n")
		res.Parse()
		fmt.Printf("\n\n\n")
	}
}
