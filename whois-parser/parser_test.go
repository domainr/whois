package parser_test

import (
	"strings"
	"testing"
	"time"

	parser "github.com/domainr/whois/whois-parser"
	"github.com/nbio/st"
)

func TestParseCommonDomainRecord_record(t *testing.T) {
	body := `Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-TLD
Registrar WHOIS Server: whois.example-registrar.tld
Registrar URL: http://www.example-registrar.tld
Updated Date: 2009-05-29T20:13:00Z
Creation Date: 2000-10-08T00:45:00Z
Registrar Registration Expiration Date: 2010-10-08T00:44:59Z
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Registrar Abuse Contact Email: email@registrar.tld
Registrar Abuse Contact Phone: +1.1235551234
Reseller: EXAMPLE RESELLER1
Domain Status: clientDeleteProhibited
Domain Status: clientRenewProhibited
Domain Status: clientTransferProhibited
Registry Registrant ID: 5372808-ERL
Registrant Name: EXAMPLE REGISTRANT
Registrant Organization: EXAMPLE ORGANIZATION
Registrant Street: 123 EXAMPLE STREET
Registrant City: ANYTOWN
Registrant State/Province: AP
Registrant Postal Code: A1A1A1
Registrant Country: AA
Registrant Phone: +1.5555551212
Registrant Phone Ext: 1234
Registrant Fax: +1.5555551213
Registrant Fax Ext: 4321
Registrant Email: EMAIL@EXAMPLE.TLD
Registry Admin ID: 5372809-ERL
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Organization: EXAMPLE REGISTRANT ORGANIZATION
Admin Street: 123 EXAMPLE STREET
Admin City: ANYTOWN
Admin State/Province: AP
Admin Postal Code: A1A1A1
Admin Country: AA
Admin Phone: +1.5555551212
Admin Phone Ext: 1234
Admin Fax: +1.5555551213
Admin Fax Ext: 1234
Admin Email: EMAIL@EXAMPLE.TLD
Registry Tech ID: 5372811-ERL
Tech Name: EXAMPLE REGISTRANT TECHNICAL
Tech Organization: EXAMPLE REGISTRANT LLC
Tech Street: 123 EXAMPLE STREET
Tech City: ANYTOWN
Tech State/Province: AP
Tech Postal Code: A1A1A1
Tech Country: AA
Tech Phone: +1.1235551234
Tech Phone Ext: 1234
Tech Fax: +1.5555551213
Tech Fax Ext: 93
Tech Email: EMAIL@EXAMPLE.TLD
Name Server: NS01.EXAMPLE-REGISTRAR.TLD10
Name Server: NS02.EXAMPLE-REGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2009-05-29T20:15:00Z <<<

Some dummy legal disclaimer
free text
more free text
`
	parse := parser.CommonDomainRecordMapping()(parser.ParseCommonDomainRecord)
	rec, err := parse(strings.NewReader(body))
	st.Assert(t, err, nil)
	st.Assert(t, rec.Type, parser.TypeDomain)

	st.Expect(t, rec.Values.Get("Domain Name"), "EXAMPLE.TLD")
	st.Expect(t, rec.Values.Get("Registry Domain ID"), "D1234567-TLD")
	st.Expect(t, rec.Values.Get("Registrar WHOIS Server"), "whois.example-registrar.tld")
	st.Expect(t, rec.Values.Get("Registrar URL"), "http://www.example-registrar.tld")
	st.Expect(t, rec.Values.Get("Updated Date"), "2009-05-29T20:13:00Z")
	st.Expect(t, rec.Values.Get("Creation Date"), "2000-10-08T00:45:00Z")
	st.Expect(t, rec.Values.Get("Registrar Registration Expiration Date"), "2010-10-08T00:44:59Z")
	st.Expect(t, rec.Values.Get("Registrar"), "EXAMPLE REGISTRAR LLC")
	st.Expect(t, rec.Values.Get("Registrar IANA ID"), "5555555")
	st.Expect(t, rec.Values.Get("Registrar Abuse Contact Email"), "email@registrar.tld")
	st.Expect(t, rec.Values.Get("Registrar Abuse Contact Phone"), "+1.1235551234")
	st.Expect(t, rec.Values.Get("Reseller"), "EXAMPLE RESELLER1")
	st.Assert(t, rec.Values["Domain Status"], []string{
		"clientDeleteProhibited",
		"clientRenewProhibited",
		"clientTransferProhibited",
	})
	st.Expect(t, rec.Values.Get("Registry Registrant ID"), "5372808-ERL")
	st.Expect(t, rec.Values.Get("Registrant Name"), "EXAMPLE REGISTRANT")
	st.Expect(t, rec.Values.Get("Registrant Organization"), "EXAMPLE ORGANIZATION")
	st.Expect(t, rec.Values.Get("Registrant Street"), "123 EXAMPLE STREET")
	st.Expect(t, rec.Values.Get("Registrant City"), "ANYTOWN")
	st.Expect(t, rec.Values.Get("Registrant State/Province"), "AP")
	st.Expect(t, rec.Values.Get("Registrant Postal Code"), "A1A1A1")
	st.Expect(t, rec.Values.Get("Registrant Country"), "AA")
	st.Expect(t, rec.Values.Get("Registrant Phone"), "+1.5555551212")
	st.Expect(t, rec.Values.Get("Registrant Phone Ext"), "1234")
	st.Expect(t, rec.Values.Get("Registrant Fax"), "+1.5555551213")
	st.Expect(t, rec.Values.Get("Registrant Fax Ext"), "4321")
	st.Expect(t, rec.Values.Get("Registrant Email"), "EMAIL@EXAMPLE.TLD")
	st.Expect(t, rec.Values.Get("Registry Admin ID"), "5372809-ERL")
	st.Expect(t, rec.Values.Get("Admin Name"), "EXAMPLE REGISTRANT ADMINISTRATIVE")
	st.Expect(t, rec.Values.Get("Admin Organization"), "EXAMPLE REGISTRANT ORGANIZATION")
	st.Expect(t, rec.Values.Get("Admin Street"), "123 EXAMPLE STREET")
	st.Expect(t, rec.Values.Get("Admin City"), "ANYTOWN")
	st.Expect(t, rec.Values.Get("Admin State/Province"), "AP")
	st.Expect(t, rec.Values.Get("Admin Postal Code"), "A1A1A1")
	st.Expect(t, rec.Values.Get("Admin Country"), "AA")
	st.Expect(t, rec.Values.Get("Admin Phone"), "+1.5555551212")
	st.Expect(t, rec.Values.Get("Admin Phone Ext"), "1234")
	st.Expect(t, rec.Values.Get("Admin Fax"), "+1.5555551213")
	st.Expect(t, rec.Values.Get("Admin Fax Ext"), "1234")
	st.Expect(t, rec.Values.Get("Admin Email"), "EMAIL@EXAMPLE.TLD")
	st.Expect(t, rec.Values.Get("Registry Tech ID"), "5372811-ERL")
	st.Expect(t, rec.Values.Get("Tech Name"), "EXAMPLE REGISTRANT TECHNICAL")
	st.Expect(t, rec.Values.Get("Tech Organization"), "EXAMPLE REGISTRANT LLC")
	st.Expect(t, rec.Values.Get("Tech Street"), "123 EXAMPLE STREET")
	st.Expect(t, rec.Values.Get("Tech City"), "ANYTOWN")
	st.Expect(t, rec.Values.Get("Tech State/Province"), "AP")
	st.Expect(t, rec.Values.Get("Tech Postal Code"), "A1A1A1")
	st.Expect(t, rec.Values.Get("Tech Country"), "AA")
	st.Expect(t, rec.Values.Get("Tech Phone"), "+1.1235551234")
	st.Expect(t, rec.Values.Get("Tech Phone Ext"), "1234")
	st.Expect(t, rec.Values.Get("Tech Fax"), "+1.5555551213")
	st.Expect(t, rec.Values.Get("Tech Fax Ext"), "93")
	st.Expect(t, rec.Values.Get("Tech Email"), "EMAIL@EXAMPLE.TLD")
	st.Assert(t, rec.Values["Name Server"], []string{
		"NS01.EXAMPLE-REGISTRAR.TLD10",
		"NS02.EXAMPLE-REGISTRAR.TLD",
	})
	st.Expect(t, rec.Values.Get("DNSSEC"), "signedDelegation")
	st.Expect(t, rec.Values.Get("URL of the ICANN WHOIS Data Problem Reporting System"), "http://wdprs.internic.net/")

	st.Expect(t, rec.DomainRecord.Disclaimer, `Some dummy legal disclaimer
free text
more free text`)

	mustTime := func(in time.Time, err error) time.Time {
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		return in
	}

	// validate parsed name server
	st.Expect(t, rec.DomainRecord.DomainName, "EXAMPLE.TLD")
	st.Expect(t, rec.DomainRecord.RegistryID, "D1234567-TLD")
	st.Expect(t, rec.DomainRecord.Registrar.WHOISServer, "whois.example-registrar.tld")
	st.Expect(t, rec.DomainRecord.Registrar.URL, "http://www.example-registrar.tld")
	st.Expect(t, rec.DomainRecord.Updated, mustTime(time.Parse("2006-01-02T15:04:05Z", "2009-05-29T20:13:00Z")))
	st.Expect(t, rec.DomainRecord.Created, mustTime(time.Parse("2006-01-02T15:04:05Z", "2000-10-08T00:45:00Z")))
	st.Expect(t, rec.DomainRecord.Expires, mustTime(time.Parse("2006-01-02T15:04:05Z", "2010-10-08T00:44:59Z")))
	st.Expect(t, rec.DomainRecord.Registrar.Name, "EXAMPLE REGISTRAR LLC")
	st.Expect(t, rec.DomainRecord.Registrar.IANAID, "5555555")
	st.Expect(t, rec.DomainRecord.Registrar.AbuseContactEmail, "email@registrar.tld")
	st.Expect(t, rec.DomainRecord.Registrar.AbuseContactPhone, "+1.1235551234")
	st.Expect(t, rec.DomainRecord.Reseller, "EXAMPLE RESELLER1")
	st.Expect(t, true, rec.DomainRecord.DomainStatus.Has(
		parser.StatusClientDeleteProhibited|
			parser.StatusClientRenewProhibited|
			parser.StatusClientTransferProhibited,
	))
	st.Expect(t, rec.DomainRecord.Registrant.RegistryID, "5372808-ERL")
	st.Expect(t, rec.DomainRecord.Registrant.Name, "EXAMPLE REGISTRANT")
	st.Expect(t, rec.DomainRecord.Registrant.Organization, "EXAMPLE ORGANIZATION")
	st.Expect(t, rec.DomainRecord.Registrant.Street, "123 EXAMPLE STREET")
	st.Expect(t, rec.DomainRecord.Registrant.City, "ANYTOWN")
	st.Expect(t, rec.DomainRecord.Registrant.StateProvince, "AP")
	st.Expect(t, rec.DomainRecord.Registrant.PostalCode, "A1A1A1")
	st.Expect(t, rec.DomainRecord.Registrant.Country, "AA")
	st.Expect(t, rec.DomainRecord.Registrant.Phone, "+1.5555551212")
	st.Expect(t, rec.DomainRecord.Registrant.PhoneExt, "1234")
	st.Expect(t, rec.DomainRecord.Registrant.Fax, "+1.5555551213")
	st.Expect(t, rec.DomainRecord.Registrant.FaxExt, "4321")
	st.Expect(t, rec.DomainRecord.Registrant.Email, "EMAIL@EXAMPLE.TLD")
	st.Expect(t, rec.DomainRecord.Admin.RegistryID, "5372809-ERL")
	st.Expect(t, rec.DomainRecord.Admin.Name, "EXAMPLE REGISTRANT ADMINISTRATIVE")
	st.Expect(t, rec.DomainRecord.Admin.Organization, "EXAMPLE REGISTRANT ORGANIZATION")
	st.Expect(t, rec.DomainRecord.Admin.Street, "123 EXAMPLE STREET")
	st.Expect(t, rec.DomainRecord.Admin.City, "ANYTOWN")
	st.Expect(t, rec.DomainRecord.Admin.StateProvince, "AP")
	st.Expect(t, rec.DomainRecord.Admin.PostalCode, "A1A1A1")
	st.Expect(t, rec.DomainRecord.Admin.Country, "AA")
	st.Expect(t, rec.DomainRecord.Admin.Phone, "+1.5555551212")
	st.Expect(t, rec.DomainRecord.Admin.PhoneExt, "1234")
	st.Expect(t, rec.DomainRecord.Admin.Fax, "+1.5555551213")
	st.Expect(t, rec.DomainRecord.Admin.FaxExt, "1234")
	st.Expect(t, rec.DomainRecord.Admin.Email, "EMAIL@EXAMPLE.TLD")
	st.Expect(t, rec.DomainRecord.Tech.RegistryID, "5372811-ERL")
	st.Expect(t, rec.DomainRecord.Tech.Name, "EXAMPLE REGISTRANT TECHNICAL")
	st.Expect(t, rec.DomainRecord.Tech.Organization, "EXAMPLE REGISTRANT LLC")
	st.Expect(t, rec.DomainRecord.Tech.Street, "123 EXAMPLE STREET")
	st.Expect(t, rec.DomainRecord.Tech.City, "ANYTOWN")
	st.Expect(t, rec.DomainRecord.Tech.StateProvince, "AP")
	st.Expect(t, rec.DomainRecord.Tech.PostalCode, "A1A1A1")
	st.Expect(t, rec.DomainRecord.Tech.Country, "AA")
	st.Expect(t, rec.DomainRecord.Tech.Phone, "+1.1235551234")
	st.Expect(t, rec.DomainRecord.Tech.PhoneExt, "1234")
	st.Expect(t, rec.DomainRecord.Tech.Fax, "+1.5555551213")
	st.Expect(t, rec.DomainRecord.Tech.FaxExt, "93")
	st.Expect(t, rec.DomainRecord.Tech.Email, "EMAIL@EXAMPLE.TLD")
	st.Assert(t, rec.DomainRecord.NameServers, []string{
		"NS01.EXAMPLE-REGISTRAR.TLD10",
		"NS02.EXAMPLE-REGISTRAR.TLD",
	})
	st.Expect(t, rec.DomainRecord.DNSSEC, parser.ParseDNSSECState("signedDelegation"))
	st.Expect(t, rec.Values.Get("URL of the ICANN WHOIS Data Problem Reporting System"), "http://wdprs.internic.net/")

	st.Expect(t, rec.DomainRecord.Disclaimer, `Some dummy legal disclaimer
free text
more free text`)

	// validate parsed domain status
	st.Expect(t, true, rec.DomainRecord.DomainStatus.Has(parser.StatusClientDeleteProhibited))
	st.Expect(t, true, rec.DomainRecord.DomainStatus.Has(parser.StatusClientRenewProhibited))
	st.Expect(t, true, rec.DomainRecord.DomainStatus.Has(parser.StatusClientTransferProhibited))
	st.Expect(t, false, rec.DomainRecord.DomainStatus.Has(parser.StatusOK))
	st.Expect(t, false, rec.DomainRecord.DomainStatus.Has(
		parser.StatusOK|
			parser.StatusClientTransferProhibited,
	))
}

func TestParseCommonDomainRecord_err(t *testing.T) {

	var err error

	// nil reader
	_, err = parser.ParseCommonDomainRecord(nil)
	if err == nil {
		t.Error("expecting err but got nil")
	} else {
		st.Expect(t, err.Error(), "given nil reader")
	}

	// invalid key-value pair lines
	_, err = parser.ParseCommonDomainRecord(strings.NewReader("Some text with no colon 1\nSome text with no colon 2"))
	if err == nil {
		t.Error("expecting err but got nil")
	} else {
		st.Expect(t, err.Error(), "invalid record format (line 1): \"Some text with no colon 1\"")
	}

	// no empty line after "Last update of WHOIS database"
	_, err = parser.ParseCommonDomainRecord(strings.NewReader(`Some Field: hello
>>> Last update of WHOIS database: 2009-05-29T20:15:00Z <<<
Some unexpected line
Some unexpected line`))
	if err == nil {
		t.Error("expecting err but got nil")
	} else {
		st.Expect(t, err.Error(), "line 3 is not empty, content: \"Some unexpected line\"")
	}

	// nothing before an empty line
	_, err = parser.ParseCommonDomainRecord(strings.NewReader(`
		Some unexpected line
		Some unexpected line`))
	if err == nil {
		t.Error("expecting err but got nil")
	} else {
		st.Expect(t, err.Error(), "parsed string contains no key-value pair")
	}

	// empty body
	_, err = parser.ParseCommonDomainRecord(strings.NewReader(""))
	if err == nil {
		t.Error("expecting err but got nil")
	} else {
		st.Expect(t, err.Error(), "parsed string contains no key-value pair")
	}
}
