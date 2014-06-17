// +build ignore

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/domainr/go-whois/tools"
	"github.com/miekg/dns"
)

var (
	url, whois  string
	v, quick    bool
	concurrency int
	dnsClient   *dns.Client
)

type Source int

const (
	None Source = 0
	IANA        = 1 << iota
	DNS
	Exception
)

var Conflicts = map[Source]string{
	None:                     "None",
	(IANA | DNS):             "IANA & DNS",
	(IANA | Exception):       "IANA & Exception",
	(DNS | Exception):        "DNS & Exception",
	(IANA | DNS | Exception): "IANA & DNS & Exception",
}

type ZoneWhois struct {
	Zone   string
	Server string
	Msg    string
	Source
}

func init() {
	flag.StringVar(
		&url,
		"url",
		"http://www.internic.net/domain/root.zone",
		"URL of the IANA root zone file. If empty, read from stdin",
	)
	flag.StringVar(
		&whois,
		"whois",
		"whois.iana.org",
		"Address of the root whois server to query",
	)
	flag.BoolVar(&v, "v", false, "verbose output (to stderr)")
	flag.BoolVar(&quick, "quick", false, "Only work on a subset of zones")
	flag.IntVar(&concurrency, "concurrency", 8, "Set maximum number of concurrent requests")
}

func main() {
	flag.Parse()

	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	var input io.Reader = os.Stdin

	if url != "" {
		fmt.Fprintf(os.Stderr, "Fetching %s\n", url)
		res, err := http.Get(url)
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("Bad GET status for %s: %d", url, res.Status)
		}
		input = res.Body
		defer res.Body.Close()
	}

	zoneMap := make(map[string]ZoneWhois)

	fmt.Fprintf(os.Stderr, "Parsing root.zone\n")
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
		zoneMap[domain] = ZoneWhois{}
	}

	// Inject exception zones
	for domain, _ := range tools.Exceptions {
		zoneMap[domain] = ZoneWhois{}
	}

	// Sort zones
	i := 0
	zones := make([]string, len(zoneMap))
	for zone, _ := range zoneMap {
		zones[i] = zone
		i++
	}
	sort.Strings(zones)

	// Quick for debugging?
	if quick {
		zones = zones[0:50]
	}

	// Get whois servers for each zone
	re := regexp.MustCompile("whois:\\s+([a-z0-9\\-\\.]+)")
	c := make(chan ZoneWhois, len(zones))
	limiter := make(chan struct{}, concurrency) // semaphore to limit concurrency

	fmt.Fprintf(os.Stderr, "Querying whois and DNS for %d zones\n", len(zones))

	// Create 1 goroutine for each zone
	for i, zone := range zones {
		go func(zone string, i int) {
			limiter <- struct{}{} // acquire semaphore

			zw := ZoneWhois{Zone: zone, Msg: "(not found)"}
			defer func() { // send result and release semaphore
				c <- zw
				<-limiter
			}()

			// First: check exception list first
			ex, ok := tools.Exceptions[zone]
			if ok {
				zw.Source |= Exception
				zw.Server = ex.Server
				zw.Msg = ex.Msg
			}

			// Second: check IANA
			res, err := querySocket(whois, zone)
			if err == nil {
				matches := re.FindStringSubmatch(res)
				if matches != nil {
					zw.Source |= IANA
					// Set if not previously found
					if zw.Server == "" {
						zw.Server = matches[1]
						zw.Msg = fmt.Sprintf("whois -h %s %s", whois, zw.Zone)
					}
				}
			}

			// Third, check whois-servers.net
			host := zone + ".whois-servers.net"
			c, err := queryCNAME(host)
			// whois-servers.net occasionally returns whois.ripe.net (unusable)
			if c != "" && c != "whois.ripe.net" && err == nil {
				zw.Source |= DNS
				// Set if not previously found
				if zw.Server == "" {
					zw.Server = c
					zw.Msg = fmt.Sprintf("dig %s CNAME", host)
				}
			}
		}(zone, i)
	}

	var numMissing, numIANA, numDNS, numExceptions, numConflicts int

	// Collect from goroutines
	for i := 0; i < len(zones); i++ {
		select {
		case zw := <-c:
			if zw.Msg == "" {
				fmt.Fprintf(os.Stderr, "No match for %s\n", zw.Zone)
			}

			zw.Server = strings.TrimSuffix(strings.ToLower(zw.Server), ".")
			zoneMap[zw.Zone] = zw

			switch {
			case zw.Server == "":
				numMissing++
			case (zw.Source & IANA) != 0:
				numIANA++
			case (zw.Source & DNS) != 0:
				numDNS++
			case (zw.Source & Exception) != 0:
				numExceptions++
			}

			if ((zw.Source & Exception) != 0) && ((zw.Source & (zw.Source - 1)) != 0) {
				numConflicts++
				if v {
					fmt.Fprintf(os.Stderr, "Conflict: %s\t(%s)\n", zw.Zone, Conflicts[zw.Source])
				}
			}
		}
	}

	// Print stats
	fmt.Fprintf(os.Stderr, "Zones with whois servers:     %d (%d via IANA, %d via DNS, %d exceptions)\n",
		len(zones)-numMissing, numIANA, numDNS, numExceptions)
	fmt.Fprintf(os.Stderr, "Zones without whois servers:  %d (%.0f%%)\n",
		numMissing, float32(numMissing)/float32(len(zones))*float32(100))
	fmt.Fprintf(os.Stderr, "Total number of zones:        %d\n",
		len(zones))
	fmt.Fprintf(os.Stderr, "Zones with conflicting data:  %d (%.0f%%)\n",
		numConflicts, float32(numConflicts)/float32(len(zones))*float32(100))

	// Generate zones.go
	buf := new(bytes.Buffer)
	const header = `// Generated by go run tools/generate.go > core/zones.go
// DO NOT EDIT

package whois

var zones = map[string]string{
`
	const footer = `}`

	buf.WriteString(header)
	for _, zone := range zones {
		zw := zoneMap[zone]
		fmt.Fprintf(buf, "\t%q: %q, // %s\n", zw.Zone, zw.Server, zw.Msg)
	}
	buf.WriteString(footer)

	// Write to stdout
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(formatted)
	return err
}

func querySocket(addr, query string) (string, error) {
	if !strings.Contains(addr, ":") {
		addr = addr + ":43"
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err = fmt.Fprint(c, query, "\r\n"); err != nil {
		return "", err
	}
	res, err := ioutil.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func queryCNAME(host string) (string, error) {
	m := new(dns.Msg)
	m.RecursionDesired = true // embedded field
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)
	dnsClient = new(dns.Client)
	r, _, err := dnsClient.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	if r.Rcode == dns.RcodeSuccess && r.Answer != nil && len(r.Answer) >= 1 {
		if cname, ok := r.Answer[0].(*dns.CNAME); ok {
			t := strings.TrimSuffix(cname.Target, ".")
			return t, nil
		}
	}
	return "", nil
}
