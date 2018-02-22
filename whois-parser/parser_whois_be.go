package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ParseBeDomainRecord parse .be whois record into values
func ParseBeDomainRecord(r io.Reader) (rec *Record, err error) {

	rec = &Record{
		Type:         TypeDomain,
		DomainRecord: &DomainRecord{},
		Values:       make(url.Values),
	}

	re := regexp.MustCompile(`Please visit [\w\.]+ for more info.`)

	s := bufio.NewScanner(r)
	for line := 1; s.Scan(); line++ {
		text := strings.Trim(s.Text(), " \n\r\t")

		if text == "" {
			// empty line, cue for the disclaimer
			continue
		}
		if text[0] == '%' {
			// all comment lines are treat as disclaimer
			rec.DomainRecord.Disclaimer += strings.TrimRight(strings.TrimLeft(text, "% "), " \n\r\t")
			continue
		}
		if re.MatchString(text) {
			// do nothing, skip
			continue
		}

		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 {
			err = fmt.Errorf("unexpected non-key-value on line %d: %#v", line, text)
			return
		}
		if len(parts[1]) != 0 {
			// read as single line value
			rec.Values.Add(
				strings.Trim(parts[0], " \n\r\t"),
				strings.Trim(parts[1], " \n\r\t"),
			)
			continue
		}

		for key := strings.Trim(parts[0], " \n\r\t"); s.Scan(); line++ {
			value := strings.Trim(s.Text(), " \n\r\t")
			if value == "" {
				break // multiline read ended
			}

			// check if this is an inner key-value line
			parts := strings.SplitN(value, ":", 2)
			if key != "Keys" && key != "Nameservers" && len(parts) == 2 {
				// inner key-value lines
				rec.Values.Add(
					strings.Trim(key+" "+parts[0], " \n\r\t"),
					strings.Trim(parts[1], " \n\r\t"),
				)
				continue
			}
			rec.Values.Add(key, strings.Trim(value, " \n\r\t"))
		}
	}
	return
}

// BeMapping is the middleware to parse values
func BeMapping() Middleware {
	mapFields := func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)
			rec.DomainRecord.DomainName = rec.Values.Get("Domain")
			rec.DomainRecord.Created = parseTime(time.Parse(
				"Mon Jan 2 2006 MST",
				rec.Values.Get("Registered")+" CET",
				// Belgium is in Central European Time (CET) zone
			))
			rec.DomainRecord.Registrar.Name =
				rec.Values.Get("Registrar Name")
			rec.DomainRecord.Registrar.URL =
				rec.Values.Get("Registrar Website")
			rec.DomainRecord.Registrar.Organization =
				rec.Values.Get("Registrar Technical Contacts Organisation")
			rec.DomainRecord.Registrar.Phone =
				rec.Values.Get("Registrar Technical Contacts Phone")
			rec.DomainRecord.Registrar.Fax =
				rec.Values.Get("Registrar Technical Contacts Fax")
			rec.DomainRecord.Registrar.Email =
				rec.Values.Get("Registrar Technical Contacts Email")
			return
		}
	}
	return Chain(
		mapFields,
		MapDomainStatus("Flags"),
		MapNameServers("Nameservers"),
	)
}
