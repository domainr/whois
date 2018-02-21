package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Parser is the abstraction for WHOIS response body parser
// that parses a given response body to a *Record, or return parse error
type Parser func(body io.Reader) (rec *Record, err error)

func parseTime(in time.Time, err error) time.Time {
	return in
}

// ParserMiddleware transform a Parser into another Parser
type ParserMiddleware func(inner Parser) Parser

// Chain chains multiple ParserMiddleware into a single one
func Chain(mwares ...ParserMiddleware) ParserMiddleware {
	return func(inner Parser) Parser {
		for i := len(mwares) - 1; i >= 0; i-- {
			inner = mwares[i](inner)
		}
		return inner
	}
}

// MapDomainInfo returns a ParserMiddleware that
// map domain related fields specified in
// ICANN's "2013 Registrar Accreditation Agreement"
func MapDomainInfo() ParserMiddleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read common fields
			rec.DomainName = rec.Values.Get("Domain Name")
			rec.RegistryID = rec.Values.Get("Registry Domain ID")
			rec.Reseller = rec.Values.Get("Reseller")
			rec.Updated = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Updated Date")))
			rec.Created = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Creation Date")))
			rec.DNSSEC = ParseDNSSECState(rec.Values.Get("DNSSEC"))
			return
		}
	}
}

// MapRegistrarInfo returns a ParserMiddleware that
// maps Registrar related information
func MapRegistrarInfo(name, expireField string) ParserMiddleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read Registrar information
			rec.Registrar = Registrar{
				Name:              rec.Values.Get(name),
				IANAID:            rec.Values.Get(name + " IANA ID"),
				WHOISServer:       rec.Values.Get(name + " WHOIS Server"),
				URL:               rec.Values.Get(name + " URL"),
				AbuseContactEmail: rec.Values.Get(name + " Abuse Contact Email"),
				AbuseContactPhone: rec.Values.Get(name + " Abuse Contact Phone"),
				RegistrationExpires: parseTime(time.Parse(
					"2006-01-02T15:04:05Z",
					rec.Values.Get(expireField),
				)),
			}
			return
		}
	}
}

// ToRegistrant sets a given Contact to a record's Registrant field
func ToRegistrant(rec *Record, c Contact) {
	rec.Registrant = c
}

// ToAdmin sets a given Contact to a record's Tech field
func ToAdmin(rec *Record, c Contact) {
	rec.Admin = c
}

// ToTech sets a given Contact to a record's Tech field
func ToTech(rec *Record, c Contact) {
	rec.Tech = c
}

// MapContact returns a ParserMiddleware that
// to map domain related fields specified in
// ICANN's "2013 Registrar Accreditation Agreement"
func MapContact(name string, mapper func(*Record, Contact)) ParserMiddleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// set the contact to rec with mapper
			mapper(
				rec,
				Contact{
					RegistryID:    rec.Values.Get("Registry " + name + " ID"),
					Name:          rec.Values.Get(name + " Name"),
					Organization:  rec.Values.Get(name + " Organization"),
					Street:        rec.Values.Get(name + " Street"),
					City:          rec.Values.Get(name + " City"),
					StateProvince: rec.Values.Get(name + " State/Province"),
					PostalCode:    rec.Values.Get(name + " Postal Code"),
					Country:       rec.Values.Get(name + " Country"),
					Phone:         rec.Values.Get(name + " Phone"),
					PhoneExt:      rec.Values.Get(name + " Phone Ext"),
					Fax:           rec.Values.Get(name + " Fax"),
					FaxExt:        rec.Values.Get(name + " Fax Ext"),
					Email:         rec.Values.Get(name + " Email"),
				},
			)
			// read name server
			if nameServers, ok := rec.Values["Name Server"]; ok {
				rec.NameServers = nameServers
			}

			// read domain status
			if domainStatuses, ok := rec.Values["Domain Status"]; ok {
				for _, status := range domainStatuses {
					rec.DomainStatus |= ParseStatusString(status)
				}
			}

			return
		}
	}
}

// MapNameServers maps the given key values to
// NameServers field
func MapNameServers(key string) ParserMiddleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read name server
			if nameServers, ok := rec.Values[key]; ok {
				rec.NameServers = nameServers
			}
			return
		}
	}
}

// MapDomainStatus maps the domain status in the given key to
// DomainStatus field
func MapDomainStatus(key string) ParserMiddleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read domain status
			if domainStatuses, ok := rec.Values["Domain Status"]; ok {
				for _, status := range domainStatuses {
					rec.DomainStatus |= ParseStatusString(status)
				}
			}
			return
		}
	}
}

// DefaultMapping implements ParserMiddleware for any
// whois record compliants to ICANN's "2013 Registrar Accreditation Agreement"
//
// ref: https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois
//
// Properly maps the rec.Values from inner into the Record fields.
func DefaultMapping() ParserMiddleware {
	return Chain(
		MapDomainInfo(),
		MapRegistrarInfo("Registrar", "Registrar Registration Expiration Date"),
		MapContact("Registrant", ToRegistrant),
		MapContact("Tech", ToTech),
		MapContact("Admin", ToAdmin),
		MapNameServers("Name Server"),
		MapDomainStatus("Domain Status"),
	)
}

// DefaultParser implements Parser for any whois record
// compliants to ICANN's "2013 Registrar Accreditation Agreement"
//
// ref: https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois
//
// Expect to receive a reader to text with 3 parts:
// 1. Key-value pairs separated by colon (":")
// 2. A line `>>> Last update of WHOIS database: [date]<<<`
// 3. Follow by an empty line, then free text of the legal disclaimers.
func DefaultParser(r io.Reader) (rec *Record, err error) {
	rec = &Record{
		Values: make(url.Values),
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

		// validate number of parts
		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 {
			err = fmt.Errorf("invalid record format (line %d): %#v", line, text)
			return
		}

		// last update line
		if parts[0] == ">>> Last update of WHOIS database" {

			// add the values
			rec.Values.Add(
				strings.TrimLeft(parts[0], ">"),
				strings.Trim(parts[1], " \n\r\t<"),
			)

			// read the supposed empty line (disclaimer cue)
			s.Scan()
			text, line = strings.Trim(s.Text(), " \n\r\t"), line+1
			if text != "" {
				err = fmt.Errorf("line %d is not empty, content: %#v", line, text)
				return
			}
			break
		}

		// add key value pair to values map
		rec.Values.Add(parts[0], strings.Trim(parts[1], " \n\r\t"))
	}

	// validate some value exists
	if len(rec.Values) == 0 {
		err = fmt.Errorf("parsed string contains no key-value pair")
		return
	}

	// read legal disclaimer
	for s.Scan() {
		rec.Disclaimer += strings.Trim(s.Text(), " \n\r\t") + "\n"
	}
	rec.Disclaimer = strings.Trim(rec.Disclaimer, " \n\r\t")
	return
}
