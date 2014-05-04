// +build ignore

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	url = flag.String("url",
		"http://www.internic.net/domain/root.zone",
		"URL of the IANA root zone file. If empty, read from stdin")
	whois = flag.String("whois",
		"whois.iana.org",
		"Address of the root whois server to query")
	v = flag.Bool("v", false, "verbose output (to stderr)")

	dnsClient *dns.Client
)

type ZoneWhois struct {
	zone  string
	whois string
	log   string
}

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

	// Sort zones
	zones := make([]string, 0, len(zoneMap))
	for zone, _ := range zoneMap {
		zones = append(zones, zone)
	}
	sort.Strings(zones)

	// Get whois servers for each zone
	re := regexp.MustCompile("whois:\\s+([a-z0-9\\-\\.]+)")
	c := make(chan ZoneWhois, len(zones))

	if *v {
		fmt.Fprintf(os.Stderr, "Querying whois servers\n")
	}

	// Create 1 goroutine for each zone
	for i, zone := range zones {
		go func(zone string, i int) {
			zw := ZoneWhois{
				zone,
				"",
				fmt.Sprintf("NO MATCH FOR %s", zone),
			}
			
			time.Sleep(time.Duration(i*100) * time.Millisecond) // Try not to hammer IANA

			res, err := querySocket(*whois, zone)
			if err != nil {
				c <- zw
				return
			}

			// Look for whois: string
			matches := re.FindStringSubmatch(res)
			if matches != nil {
				zw.whois = matches[1]
				zw.log = fmt.Sprintf("whois -h %s %s\t\t%s", *whois, zw.zone, zw.whois)
				c <- zw
				return
			}

			// Check whois-servers.net
			host := zone + ".whois-servers.net"
			cname, err := queryCNAME(host)
			if cname == "" || err != nil {
				c <- zw
				return
			}

			zw.whois = cname
			zw.log = fmt.Sprintf("dig %s CNAME\t\t%s", host, zw.whois)
			c <- zw
		}(zone, i)
	}

	// Collect from goroutines
	for i := 0; i < len(zones); i++ {
		select {
		case zw := <-c:
			if *v {
				fmt.Fprintf(os.Stderr, "%s\n", zw.log)
			}
		}
	}

	return nil
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
	m.RecursionDesired = true
	fqdn := dns.Fqdn(host)
	m.SetQuestion(fqdn, dns.TypeCNAME)
	dnsClient = new(dns.Client)
	r, _, err := dnsClient.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return "", err
	} else if r.Rcode == dns.RcodeSuccess && r.Answer != nil && len(r.Answer) >= 1 {
		return r.Answer[0].Header().Name, nil
	}
	return "", nil
}
