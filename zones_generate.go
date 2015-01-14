// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/domainr/whois"
	"github.com/miekg/dns"
)

type override struct {
	server string
	msg    string
}

var baseOverrides = map[string]override{
	"al":               override{"www.akep.al", "web (CAPTCHA) http://www.akep.al/sq/kerkoni-domain"},
	"ar":               override{"nic.ar", "web (CAPTCHA)"},
	"az":               override{"www.whois.az", "web (POST)"},
	"ba":               override{"nic.ba", "web (POST)"},
	"bd":               override{"www.whois.com.bd", "web"},
	"bm":               override{"www.bermudanic.bm", "web (POST)"},
	"bs":               override{"www.register.bs", "web"},
	"bt":               override{"www.nic.bt", "web (POST)"},
	"bv":               override{"whois.norid.no", "http://www.norid.no/navnepolitikk.en.html#link1"},
	"cm":               override{"antic.cm", "web (sessioned)"},
	"cr":               override{"www.nic.cr", "web (CAPTCHA)"},
	"cu":               override{"www.nic.cu", "web"},
	"cv":               override{"www.dns.cv", "web"},
	"cy":               override{"www.nic.cy", "web"},
	"dj":               override{"www.dj", "web"},
	"eg":               override{"lookup.egregistry.eg", "web (POST)"},
	"fj":               override{"domains.fj", "web "},
	"fk":               override{"whois.marcaria.com", "web"},
	"ge":               override{"www.nic.net.ge", "web (POST)"},
	"gf":               override{"www.dom-enic.com", "web (POST)"},
	"gm":               override{"www.nic.gm", "web"},
	"gmo":              override{"whois.gmoregistry.net", "http://en.wikipedia.org/wiki/.gmo"},
	"gp":               override{"www.dom-enic.com", "web (POST)"},
	"gr":               override{"grweb.ics.forth.gr", "web (CAPTCHA)"},
	"gt":               override{"www.gt", "web"},
	"kw":               override{"www.kw", "web (POST)"},
	"ky":               override{"kynseweb.messagesecure.com", "web (POST)"},
	"lb":               override{"www.aub.edu.lb", "web"},
	"lc":               override{"www.nic.lc", "web (POST)"},
	"lk":               override{"whois.nic.lk", "http://nic.lk"},
	"ls":               override{"www.co.ls", "web"},
	"mq":               override{"www.dom-enic.com", "web (POST)"},
	"mt":               override{"www.nic.org.mt", "web"},
	"mw":               override{"www.registrar.mw", "web"},
	"mz":               override{"www.domains.co.mz", "web (CAPTCHA)"},
	"ni":               override{"www.nic.ni", "web (POST AJAX)"},
	"np":               override{"register.mos.com.np", "web (POST)"},
	"nr":               override{"cenpac.net.nr", "http://cenpac.net.nr/dns/"},
	"pa":               override{"www.nic.pa", "web"},
	"ph":               override{"www.dot.ph", "web (CAPTCHA)"},
	"pk":               override{"pk6.pknic.net.pk", "web"},
	"pn":               override{"www.government.pn", "web (POST)"},
	"py":               override{"www.nic.py", "web (POST)"},
	"rw":               override{"whois.ricta.org.rw", "web"},
	"sj":               override{"whois.norid.no", "http://www.norid.no/navnepolitikk.en.html#link1"},
	"sl":               override{"www.nic.sl", "web"},
	"sr":               override{"www.register.sr", "web (CAPTCHA)"},
	"tg":               override{"www.netmaster.tg", "web"},
	"tj":               override{"www.nic.tj", "web"},
	"tt":               override{"www.nic.tt", "web"},
	"va":               override{"whois.iana.org", "Every .va domain name owned by the Vatican"},
	"vi":               override{"secure.nic.vi", "web (POST)"},
	"vn":               override{"whois.vnnic.vn", "web"},
	"xn--90a3ac":       override{"whois.rnids.rs", "http://en.wikipedia.org/wiki/.xn--90a3ac"},
	"xn--fzc2c9e2c":    override{"whois.nic.lk", "http://www.iana.org/domains/root/db/.xn--fzc2c9e2c.html"},
	"xn--mgbc0a9azcg":  override{"whois.iam.net.ma", "Morocco"},
	"xn--pgbs0dh":      override{"whois.ati.tn", "Tunisia"},
	"xn--rhqv96g":      override{"whois.nic.xn--rhqv96g", "China"},
	"xn--ses554g":      override{"whois.gtld.knet.cn", "China: whois -h whois.gtld.knet.cn nic.xn--ses554g"},
	"xn--xkc2al3hye2a": override{"whois.nic.lk", "Sri Lanka"},
	"za":               override{"whois.registry.net.za", "http://en.wikipedia.org/wiki/.za"},
	"zw":               override{"www.zispa.org.zw", "web"},
}

type source int

const (
	none       source = 0
	sourceIANA        = 1 << iota
	sourceDNS
	sourceOverride
)

var Conflicts = map[source]string{
	none: "None",
	(sourceIANA | sourceDNS):                  "IANA & DNS",
	(sourceIANA | sourceOverride):             "IANA & override",
	(sourceDNS | sourceOverride):              "DNS & override",
	(sourceIANA | sourceDNS | sourceOverride): "IANA & DNS & override",
}

type zoneWhois struct {
	zone   string
	server string
	msg    string
	source
}

var (
	rootZoneURL    string
	overrideURL    string
	server         string
	v, quick       bool
	concurrency    int
	dnsClient      = &dns.Client{Net: "tcp"}
	_, _file, _, _ = runtime.Caller(0)
	_filename      = filepath.Base(_file)
	_dir           = filepath.Dir(_file)
)

func init() {
	flag.StringVar(
		&rootZoneURL,
		"root",
		"http://www.internic.net/domain/root.zone",
		"URL of the IANA root zone file, or - to read from stdin",
	)
	flag.StringVar(
		&overrideURL,
		"override",
		"https://github.com/weppos/whois/raw/master/data/tld.json",
		"URL of the Ruby Whois tld.json override file, or - to read from stdin",
	)
	flag.StringVar(
		&server,
		"server",
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
	// Fetch root.zone
	zoneMap, err := fetchRootZone(rootZoneURL)
	if err != nil {
		return err
	}

	// Fetch overrides
	overrides, err := fetchOverrides(overrideURL)
	if err != nil {
		return err
	}

	// Inject override zones
	for domain, _ := range overrides {
		zoneMap[domain] = zoneWhois{}
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
	c := make(chan zoneWhois, len(zones))
	limiter := make(chan struct{}, concurrency) // semaphore to limit concurrency

	fmt.Fprintf(os.Stderr, "Querying whois and DNS for %d zones\n", len(zones))

	// Create 1 goroutine for each zone
	for i, zone := range zones {
		go func(zone string, i int) {
			limiter <- struct{}{} // acquire semaphore

			zw := zoneWhois{zone: zone, msg: "(not found)"}
			defer func() { // send result and release semaphore
				c <- zw
				<-limiter
			}()

			// First: check override list
			ov, ok := overrides[zone]
			if ok {
				zw.source |= sourceOverride
				zw.server = ov.server
				zw.msg = "Override: " + ov.msg
			}

			// Check whois-servers.net
			host := zone + ".whois-servers.net"
			c, err := queryCNAME(host)
			// whois-servers.net occasionally returns whois.ripe.net (unusable)
			if c != "" && c != "whois.ripe.net" && err == nil {
				zw.source |= sourceDNS
				// Set if equal or not previously found
				if zw.server == c || zw.server == "" {
					zw.server = c
					zw.msg = fmt.Sprintf("dig %s CNAME", host)
				}
			}

			// Check IANA
			res, err := querySocket(server, zone)
			if err == nil {
				matches := re.FindStringSubmatch(res)
				if matches != nil {
					zw.source |= sourceIANA
					// Set if equal or not previously found
					if zw.server == matches[1] || zw.server == "" {
						zw.server = matches[1]
						zw.msg = fmt.Sprintf("whois -h %s %s", server, zw.zone)
					}
				}
			}
		}(zone, i)
	}

	var numAdded, numChanged, numLost, numMissing, numIANA, numDNS, numOverrides, numConflicts int

	// Collect from goroutines
	for i := 0; i < len(zones); i++ {
		select {
		case zw := <-c:
			if zw.msg == "" {
				fmt.Fprintf(os.Stderr, "No match for %s\n", zw.zone)
			}

			prev, _ := whois.Resolve("test." + zw.zone)
			switch {
			case zw.server != "" && prev == "":
				numAdded++
			case zw.server == "" && prev != "":
				fmt.Fprintf(os.Stderr, "%s lost; previously %s\n", zw.zone, prev)
				numLost++
				numChanged++
			case zw.server != prev:
				fmt.Fprintf(os.Stderr, "%s changed from %s to %s\n", zw.zone, prev, zw.server)
				numChanged++
			}

			zw.server = strings.TrimSuffix(strings.ToLower(zw.server), ".")
			zoneMap[zw.zone] = zw

			switch {
			case zw.server == "":
				numMissing++
			case (zw.source & sourceIANA) != 0:
				numIANA++
			case (zw.source & sourceDNS) != 0:
				numDNS++
			case (zw.source & sourceOverride) != 0:
				numOverrides++
			}

			if ((zw.source & sourceOverride) != 0) && ((zw.source & (zw.source - 1)) != 0) {
				numConflicts++
				if v {
					fmt.Fprintf(os.Stderr, "Conflict: %s\t(%s)\n", zw.zone, Conflicts[zw.source])
				}
			}
		}
	}

	// Print stats
	fmt.Fprintf(os.Stderr, "Zones with whois servers:     %d (%d via IANA, %d via DNS, %d overrides)\n",
		len(zones)-numMissing, numIANA, numDNS, numOverrides)
	fmt.Fprintf(os.Stderr, "Zones without whois servers:  %d (%.0f%%)\n",
		numMissing, float32(numMissing)/float32(len(zones))*float32(100))
	fmt.Fprintf(os.Stderr, "Total number of zones:        %d\n",
		len(zones))
	fmt.Fprintf(os.Stderr, "Zones with conflicting data:  %d (%.0f%%)\n",
		numConflicts, float32(numConflicts)/float32(len(zones))*float32(100))
	fmt.Fprintf(os.Stderr, "Zones added:                  %d (%.0f%%)\n",
		numAdded, float32(numAdded)/float32(len(zones))*float32(100))
	fmt.Fprintf(os.Stderr, "Zones changed:                %d (%.0f%%)\n",
		numChanged, float32(numChanged)/float32(len(zones))*float32(100))
	fmt.Fprintf(os.Stderr, "Zones lost:                   %d (%.0f%%)\n",
		numLost, float32(numLost)/float32(len(zones))*float32(100))

	// Generate zones.go
	buf := new(bytes.Buffer)
	header := `// Generated from:
// go generate (Go >= 1.4)
// go run ` + _filename + ` (Go <= 1.3)
// DO NOT EDIT

package whois

var zones = map[string]string{
`
	footer := `}`

	buf.WriteString(header)
	for _, zone := range zones {
		zw := zoneMap[zone]
		fmt.Fprintf(buf, "\t%q: %q, // %s\n", zw.zone, zw.server, zw.msg)
	}
	buf.WriteString(footer)

	// gofmt
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}

	// Write to zones.go
	fn := filepath.Join(_dir, "zones.go")
	f, err := os.Create(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating zones.go: %s\n", err)
		return err
	}
	defer f.Close()

	_, err = f.Write(formatted)
	return err
}

func fetchRootZone(u string) (map[string]zoneWhois, error) {
	var input io.Reader = os.Stdin

	if u != "-" {
		res, err := fetch(u)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		input = res.Body
	}

	zoneMap := make(map[string]zoneWhois)

	fmt.Fprintf(os.Stderr, "Parsing root.zone\n")
	for token := range dns.ParseZone(input, "", "") {
		if token.Error != nil {
			return nil, token.Error
		}
		header := token.RR.Header()
		if header.Rrtype != dns.TypeNS {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(header.Name), ".")
		if domain == "" {
			continue
		}
		zoneMap[domain] = zoneWhois{}
	}

	return zoneMap, nil
}

func fetchOverrides(u string) (map[string]override, error) {
	var input io.Reader = os.Stdin

	if u != "-" {
		res, err := fetch(u)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		input = res.Body
	}

	type rubyOverride struct {
		Host    string `json:"host"`
		Adapter string `json:"adapter"`
		URL     string `json:"url"`
	}
	rubyOverrides := make(map[string]rubyOverride)

	fmt.Fprintf(os.Stderr, "Parsing overrides\n")
	d := json.NewDecoder(input)
	err := d.Decode(&rubyOverrides)
	if err != nil {
		return nil, err
	}

	// Copy Ruby Whois overrides
	overrides := make(map[string]override)
	for d, ro := range rubyOverrides {
		o := override{ro.Host, "Ruby Whois"}

		// Parse host from URL
		if ro.URL != "" {
			o.msg += " (web): " + ro.URL
			u, err := url.Parse(ro.URL)
			if err != nil {
				return nil, err
			}
			o.server = u.Host
		}

		// Add to overrides
		d = strings.TrimPrefix(d, ".")
		if _, ok := overrides[d]; ok && o.server == "" {
			continue
		}
		overrides[d] = o
	}

	// Inject base overrides
	for d, o := range baseOverrides {
		overrides[d] = o
	}

	fmt.Printf("%d overrides, %d from Ruby Whois\n", len(overrides), len(rubyOverrides))

	return overrides, nil
}

func fetch(u string) (*http.Response, error) {
	fmt.Fprintf(os.Stderr, "Fetching %s\n", u)
	res, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error for %s: %d", u, res.Status)
	}
	return res, nil
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
