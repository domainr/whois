package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// ParseDENICDomainRecord parse whois response from DENIC into
// Values.
func ParseDENICDomainRecord(r io.Reader) (rec *Record, err error) {
	rec = &Record{
		Type:         TypeDomain,
		DomainRecord: &DomainRecord{},
		Values:       make(url.Values),
	}
	prefix := ""

	s := bufio.NewScanner(r)
	for line := 1; s.Scan(); line++ {
		text := strings.Trim(s.Text(), " \n\r\t")

		if text == "" {
			// empty line, cue for the disclaimer
			prefix = ""
			continue
		}
		if text[0] == '%' {
			rec.DomainRecord.Disclaimer += strings.TrimRight(strings.TrimLeft(text, "% "), " \n\r\t")
			continue
		}
		if text[0] == '[' && text[len(text)-1] == ']' {
			prefix = strings.Trim(text, " []\n\r\t") + " "
			continue
		}

		// validate number of parts
		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 {
			err = fmt.Errorf("invalid record format (line %d): %#v", line, text)
			return
		}

		// add key value pair to values map
		rec.Values.Add(prefix+parts[0], strings.Trim(parts[1], " \n\r\t"))
	}

	// validate some value exists
	if len(rec.Values) == 0 {
		err = fmt.Errorf("parsed string contains no key-value pair")
		return
	}
	return

}

// DENICMapping map DENIC values
func DENICMapping() Middleware {
	mapFields := func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)
			rec.DomainRecord.DomainName = rec.Values.Get("Domain")
			status := strings.ToLower(rec.Values.Get("Status"))
			if status == "free" {
				err = ErrorDomainNotFound
				return
			}
			if status == "connect" {
				rec.DomainRecord.DomainStatus = StatusOK
			}

			rec.DomainRecord.Updated = parseTime(time.Parse("2006-01-02T15:04:05-07:00", rec.Values.Get("Changed")))

			// Tech-C section
			rec.DomainRecord.Tech.Name = rec.Values.Get("Tech-C Name")
			rec.DomainRecord.Tech.Organization = rec.Values.Get("Tech-C Organisation")
			rec.DomainRecord.Tech.Street = rec.Values.Get("Tech-C Address")
			rec.DomainRecord.Tech.PostalCode = rec.Values.Get("Tech-C PostalCode")
			rec.DomainRecord.Tech.City = rec.Values.Get("Tech-C City")
			rec.DomainRecord.Tech.Country = rec.Values.Get("Tech-C CountryCode")
			rec.DomainRecord.Tech.Phone = rec.Values.Get("Tech-C Phone")
			rec.DomainRecord.Tech.Fax = rec.Values.Get("Tech-C Fax")
			rec.DomainRecord.Tech.Email = rec.Values.Get("Tech-C Email")
			rec.DomainRecord.Tech.Remarks = rec.Values.Get("Tech-C Remarks")
			rec.DomainRecord.Tech.Updated = parseTime(time.Parse("2006-01-02T15:04:05-07:00", rec.Values.Get("Tech-C Changed")))

			// TODO: Zone-C is not handled. Need to figure out a way to handle it
			return
		}
	}
	return Chain(
		mapFields,
		MapDomainStatus("Status"),
		MapNameServers("Nserver"),
	)
}
