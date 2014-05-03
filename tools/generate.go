// +build ignore

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

var (
	url = flag.String("url",
		"http://www.internic.net/domain/root.zone",
		"URL of the IANA root zone file. If empty, read from stdin")
	v = flag.Bool("v", false, "verbose output (to stderr)")
)

func main() {
	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	flag.Parse()

	var input io.Reader = os.Stdin

	if *url != "" {
		if *v {
			fmt.Fprintf(os.Stderr, "Fetching %s\n", *url)
		}
		res, err := http.Get(*url)
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("Bad GET status for %s: %d", *url, res.Status)
		}
		input = res.Body
		defer res.Body.Close()
	}

	zoneMap := make(map[string]string)

	if *v {
		fmt.Fprintf(os.Stderr, "Parsing root.zone\n")
	}
	for token := range dns.ParseZone(input, "", "") {
		if token.Error != nil {
			return token.Error
		}
		header := token.RR.Header()
		if header.Rrtype != dns.TypeNS {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(header.Name), ".")
		if domain == "" {
			continue
		}
		zoneMap[domain] = domain
	}

	zones := make([]string, 0, len(zoneMap))
	for zone, _ := range zoneMap {
		zones = append(zones, zone)
	}
	sort.Strings(zones)

	for _, zone := range zones {
		fmt.Println(zone)
	}

	return nil
}
