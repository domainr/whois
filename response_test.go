package whois

import (
	"fmt"
	"os"
	"testing"

	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestReadMIME(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		fmt.Printf("%s\n", fn)
		res, err := readMIMEFile(fn)
		if res != nil && err != nil {
			fmt.Fprintf(os.Stderr, "Error reading MIME file: %s\n", err.Error())
			res.DetectContentType("")
		}
		// st.Assert(t, err, nil)
		res.Body = make([]byte, 0)
		fmt.Printf("%#v\n\n", res)
	}
}

func readMIMEFile(fn string) (*Response, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadMIME(f)
}
