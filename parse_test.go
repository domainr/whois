package whois

import (
	"fmt"
	"testing"

	"github.com/domainr/whoistest"
	"github.com/nbio/st"
)

func TestResponseFiles(t *testing.T) {
	fns, err := whoistest.ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		fmt.Printf("%s\n", fn)
	}
}
