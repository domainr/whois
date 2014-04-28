package main

import (
	"flag"
	"fmt"
	"os"
	
	"github.com/domainr/go-whois"
)

func main() {
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

	info, err := whois.Whois(query)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(info)
	}
}
