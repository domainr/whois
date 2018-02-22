package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// ParseCNNICDomainRecord implements Parser for CNNIC
//
// Expect to receive a reader of text with lines
// Key-value pairs separated by colon (":").
func ParseCNNICDomainRecord(r io.Reader) (rec *Record, err error) {
	rec = &Record{
		Type:         TypeDomain,
		DomainRecord: &DomainRecord{},
		Values:       make(url.Values),
	}
	if r == nil {
		err = fmt.Errorf("given nil reader")
		return
	}

	s := bufio.NewScanner(r)
	for line := 1; s.Scan(); line++ {
		text := strings.Trim(s.Text(), " \n\r\t")
		if text == "" {
			// empty line, cue for the disclaimer
			break
		}

		if line == 1 {
			if text == "the Domain Name you apply can not be registered online. Please consult your Domain Name registrar" {
				err = ErrorDomainReserved
				return
			}
			if text == "the domain you want to register is reserved." {
				err = ErrorDomainReserved
				return
			}
			if text == "no matching record." {
				err = ErrorDomainNotFound
				return
			}
		}

		// validate number of parts
		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 {
			err = fmt.Errorf("invalid record format (line %d): %#v", line, text)
			return
		}

		// add key value pair to values map
		rec.Values.Add(parts[0], strings.Trim(parts[1], " \n\r\t"))
	}

	// validate some value exists
	if len(rec.Values) == 0 {
		err = fmt.Errorf("parsed string contains no key-value pair")
		return
	}
	return
}

// CNNICMapping maps values to DomainRecord
func CNNICMapping() Middleware {
	mapFields := func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)
			rec.DomainRecord.DomainName = rec.Values.Get("Domain Name")
			rec.DomainRecord.RegistryID = rec.Values.Get("ROID")
			rec.DomainRecord.Registrant.Name = rec.Values.Get("Registrant")
			rec.DomainRecord.Registrant.RegistryID = rec.Values.Get("Registrant ID")
			rec.DomainRecord.Registrant.Email = rec.Values.Get("Registrant Contact Email")
			rec.DomainRecord.Created = parseTime(time.Parse("2006-01-02 15:04:05", rec.Values.Get("Registration Time")))
			rec.DomainRecord.Expires = parseTime(time.Parse("2006-01-02 15:04:05", rec.Values.Get("Expiration Time")))
			rec.DomainRecord.DNSSEC = ParseDNSSECState(rec.Values.Get("DNSSEC"))
			return
		}
	}
	return Chain(
		mapFields,
		MapDomainStatus("Domain Status"),
		MapNameServers("Name Server"),
	)
}
