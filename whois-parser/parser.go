package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Error represents error
type Error int

// Error implements error interface
func (err Error) Error() string {
	switch err {
	case ErrorDomainReserved:
		return "domain is reserved and not available for registration"
	case ErrorDomainNotFound:
		return "domain not found"
	}
	return "unknown error"
}

// Different Error in parsing the response
const (
	_ Error = iota
	ErrorDomainReserved
	ErrorDomainNotFound
)

// Parser is the abstraction for WHOIS response body parser
// that parses a given response body to a *Record, or return parse error
type Parser func(body io.Reader) (rec *Record, err error)

func parseTime(in time.Time, err error) time.Time {
	return in
}

// Middleware transform a Parser into another Parser
type Middleware func(inner Parser) Parser

// Chain chains multiple Middleware into a single one
func Chain(mwares ...Middleware) Middleware {
	return func(inner Parser) Parser {
		for i := len(mwares) - 1; i >= 0; i-- {
			inner = mwares[i](inner)
		}
		return inner
	}
}

// MapDomainInfo returns a Middleware that
// map domain related fields specified in
// ICANN's "2013 Registrar Accreditation Agreement"
func MapDomainInfo() Middleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read common fields
			rec.DomainRecord.DomainName = rec.Values.Get("Domain Name")
			rec.DomainRecord.RegistryID = rec.Values.Get("Registry Domain ID")
			rec.DomainRecord.Reseller = rec.Values.Get("Reseller")
			rec.DomainRecord.Updated = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Updated Date")))
			rec.DomainRecord.Created = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Creation Date")))
			rec.DomainRecord.DNSSEC = ParseDNSSECState(rec.Values.Get("DNSSEC"))
			rec.DomainRecord.Expires = parseTime(time.Parse(
				"2006-01-02T15:04:05Z",
				rec.Values.Get("Registrar Registration Expiration Date"),
			))

			return
		}
	}
}

// MapRegistrarInfo returns a Middleware that
// maps Registrar related information
func MapRegistrarInfo(name string) Middleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read Registrar information
			rec.DomainRecord.Registrar = Registrar{
				Name:              rec.Values.Get(name),
				IANAID:            rec.Values.Get(name + " IANA ID"),
				WHOISServer:       rec.Values.Get(name + " WHOIS Server"),
				URL:               rec.Values.Get(name + " URL"),
				AbuseContactEmail: rec.Values.Get(name + " Abuse Contact Email"),
				AbuseContactPhone: rec.Values.Get(name + " Abuse Contact Phone"),
			}
			return
		}
	}
}

// ToDomainRegistrant sets a given Contact to a record.DomainRecord.Registrant
func ToDomainRegistrant(rec *Record, c Contact) {
	rec.DomainRecord.Registrant = c
}

// ToDomainAdmin sets a given Contact to a record.DomainRecord.Admin
func ToDomainAdmin(rec *Record, c Contact) {
	rec.DomainRecord.Admin = c
}

// ToDomainTech sets a given Contact to a record.DomainRecord.Tech
func ToDomainTech(rec *Record, c Contact) {
	rec.DomainRecord.Tech = c
}

// MapContact returns a Middleware that
// to map domain related fields specified in
// ICANN's "2013 Registrar Accreditation Agreement"
func MapContact(name string, mapper func(*Record, Contact)) Middleware {
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
			return
		}
	}
}

// MapNameServers maps the given key values to
// NameServers field
func MapNameServers(key string) Middleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read name servers, set to DomainRecord if it is not empty
			if nameServers, ok := rec.Values[key]; ok {
				rec.DomainRecord.NameServers = make([]string, 0, len(nameServers))
				for i := range nameServers {
					if nameServers[i] != "" {
						rec.DomainRecord.NameServers = append(
							rec.DomainRecord.NameServers,
							nameServers[i],
						)
					}
				}
			}
			return
		}
	}
}

// MapDomainStatus maps the domain status in the given key to
// DomainStatus field
func MapDomainStatus(key string) Middleware {
	return func(inner Parser) Parser {
		return func(r io.Reader) (rec *Record, err error) {
			rec, err = inner(r)

			// read domain status
			if domainStatuses, ok := rec.Values["Domain Status"]; ok {
				for _, status := range domainStatuses {
					rec.DomainRecord.DomainStatus |= ParseStatusString(status)
				}
			}
			return
		}
	}
}

// CommonDomainRecordMapping implements Middleware for any
// whois record compliants to ICANN's "2013 Registrar Accreditation Agreement"
//
// ref: https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois
//
// Properly maps the rec.Values from inner into the Record fields.
func CommonDomainRecordMapping() Middleware {
	return Chain(
		MapDomainInfo(),
		MapRegistrarInfo("Registrar"),
		MapContact("Registrant", ToDomainRegistrant),
		MapContact("Tech", ToDomainTech),
		MapContact("Admin", ToDomainAdmin),
		MapNameServers("Name Server"),
		MapDomainStatus("Domain Status"),
	)
}

// ParseCommonDomainRecord implements Parser for any whois record
// compliants to ICANN's "2013 Registrar Accreditation Agreement"
//
// ref: https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois
//
// Expect to receive a reader to text with 3 parts:
// 1. Key-value pairs separated by colon (":")
// 2. A line `>>> Last update of WHOIS database: [date]<<<`
// 3. Follow by an empty line, then free text of the legal disclaimers.
func ParseCommonDomainRecord(r io.Reader) (rec *Record, err error) {
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
		rec.DomainRecord.Disclaimer += strings.Trim(s.Text(), " \n\r\t") + "\n"
	}
	rec.DomainRecord.Disclaimer = strings.Trim(rec.DomainRecord.Disclaimer, " \n\r\t")
	return
}
