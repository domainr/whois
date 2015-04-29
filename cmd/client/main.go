// +build ignore

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/domainr/whois"
	"github.com/domainr/whoistest"
)

func main() {
	test := flag.Bool("t", false, "load from whois test data instead of the network")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments] <domain>\n\nAvailable arguments:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()
	query := flag.Arg(0)

	if query == "" {
		flag.Usage()
	}

	req, err := whois.NewRequest(query)
	FatalIf(err)

	var res *whois.Response
	if *test {
		fns, err := whoistest.ResponseFiles()
		FatalIf(err)

		// FIXME: UNIX-specific
		sfx := "/" + query + ".mime"
		fmt.Fprintf(os.Stderr, "Looking for test file ...%s\n", sfx)
		// FIXME: slow
		for _, fn := range fns {
			if strings.HasSuffix(fn, sfx) {
				res, err = whois.ReadMIMEFile(fn)
				FatalIf(err)
				break
			}
		}
	} else {
		res, err = whois.DefaultClient.Fetch(req)
		FatalIf(err)
	}

	fmt.Println(res.String())
}

func FatalIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(-1)
}
