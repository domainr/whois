package whois

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

// DefaultParser implements Parser for any whois record
// compliants to ICANN's "2013 Registrar Accreditation Agreement"
//
// ref: https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois
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

	// read common fields
	rec.DomainName = rec.Values.Get("Domain Name")
	rec.RegistryID = rec.Values.Get("Registry Domain ID")
	rec.Reseller = rec.Values.Get("Reseller")
	rec.Updated = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Updated Date")))
	rec.Created = parseTime(time.Parse("2006-01-02T15:04:05Z", rec.Values.Get("Creation Date")))
	rec.DNSSEC = ParseDNSSECState(rec.Values.Get("DNSSEC"))
	rec.Registrar = Registrar{
		Name:              rec.Values.Get("Registrar"),
		IANAID:            rec.Values.Get("Registrar IANA ID"),
		WHOISServer:       rec.Values.Get("Registrar WHOIS Server"),
		URL:               rec.Values.Get("Registrar URL"),
		AbuseContactEmail: rec.Values.Get("Registrar Abuse Contact Email"),
		AbuseContactPhone: rec.Values.Get("Registrar Abuse Contact Phone"),
		RegistrationExpires: parseTime(time.Parse(
			"2006-01-02T15:04:05Z",
			rec.Values.Get("Registrar Registration Expiration Date"),
		)),
	}
	rec.Registrant = Contact{
		RegistryID:    rec.Values.Get("Registry Registrant ID"),
		Name:          rec.Values.Get("Registrant Name"),
		Organization:  rec.Values.Get("Registrant Organization"),
		Street:        rec.Values.Get("Registrant Street"),
		City:          rec.Values.Get("Registrant City"),
		StateProvince: rec.Values.Get("Registrant State/Province"),
		PostalCode:    rec.Values.Get("Registrant Postal Code"),
		Country:       rec.Values.Get("Registrant Country"),
		Phone:         rec.Values.Get("Registrant Phone"),
		PhoneExt:      rec.Values.Get("Registrant Phone Ext"),
		Fax:           rec.Values.Get("Registrant Fax"),
		FaxExt:        rec.Values.Get("Registrant Fax Ext"),
		Email:         rec.Values.Get("Registrant Email"),
	}
	rec.Admin = Contact{
		RegistryID:    rec.Values.Get("Registry Admin ID"),
		Name:          rec.Values.Get("Admin Name"),
		Organization:  rec.Values.Get("Admin Organization"),
		Street:        rec.Values.Get("Admin Street"),
		City:          rec.Values.Get("Admin City"),
		StateProvince: rec.Values.Get("Admin State/Province"),
		PostalCode:    rec.Values.Get("Admin Postal Code"),
		Country:       rec.Values.Get("Admin Country"),
		Phone:         rec.Values.Get("Admin Phone"),
		PhoneExt:      rec.Values.Get("Admin Phone Ext"),
		Fax:           rec.Values.Get("Admin Fax"),
		FaxExt:        rec.Values.Get("Admin Fax Ext"),
		Email:         rec.Values.Get("Admin Email"),
	}
	rec.Tech = Contact{
		RegistryID:    rec.Values.Get("Registry Tech ID"),
		Name:          rec.Values.Get("Tech Name"),
		Organization:  rec.Values.Get("Tech Organization"),
		Street:        rec.Values.Get("Tech Street"),
		City:          rec.Values.Get("Tech City"),
		StateProvince: rec.Values.Get("Tech State/Province"),
		PostalCode:    rec.Values.Get("Tech Postal Code"),
		Country:       rec.Values.Get("Tech Country"),
		Phone:         rec.Values.Get("Tech Phone"),
		PhoneExt:      rec.Values.Get("Tech Phone Ext"),
		Fax:           rec.Values.Get("Tech Fax"),
		FaxExt:        rec.Values.Get("Tech Fax Ext"),
		Email:         rec.Values.Get("Tech Email"),
	}

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
