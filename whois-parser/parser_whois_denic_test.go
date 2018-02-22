package parser_test

import (
	"strings"
	"testing"
	"time"

	parser "github.com/domainr/whois/whois-parser"
	"github.com/nbio/st"
)

func TestParseDENICDomainRecord_normal(t *testing.T) {
	r := strings.NewReader(`% Copyright (c) 2010 by DENIC
% Version: 2.0
%
% Restricted rights.
%
% Terms and Conditions of Use
%
% The data in this record is provided by DENIC for informational purposes only.
% DENIC does not guarantee its accuracy and cannot, under any circumstances,
% be held liable in case the stored information would prove to be wrong,
% incomplete or not accurate in any sense.
%
% All the domain data that is visible in the whois service is protected by law.
% It is not permitted to use it for any purpose other than technical or
% administrative requirements associated with the operation of the Internet.
% It is explicitly forbidden to extract, copy and/or use or re-utilise in any
% form and by any means (electronically or not) the whole or a quantitatively
% or qualitatively substantial part of the contents of the whois database
% without prior and explicit written permission by DENIC.
% It is prohibited, in particular, to use it for transmission of unsolicited
% and/or commercial and/or advertising by phone, fax, e-mail or for any similar
% purposes.
%
% By maintaining the connection you assure that you have a legitimate interest
% in the data and that you will only use it for the stated purposes. You are
% aware that DENIC maintains the right to initiate legal proceedings against
% you in the event of any breach of this assurance and to bar you from using
% its whois service.
%
% The DENIC whois service on port 43 never discloses any information concerning
% the domain holder/administrative contact. Information concerning the domain
% holder/administrative contact can be obtained through use of our web-based
% whois service available at the DENIC website:
% http://www.denic.de/en/domains/whois-service/web-whois.html
%

Domain: denic.de
Nserver: ns1.denic.de 2001:668:1f:11:0:0:0:106 77.67.63.106
Nserver: ns2.denic.de 78.104.145.26
Nserver: ns3.denic.de 81.91.173.19
Dnskey: 257 3 8 AwEAAb/xrM2MD+xm84YNYby6TxkMaC6PtzF2bB9WBB7ux7iqzhViob4GKvQ6L7CkXjyAxfKbTzrdvXoAPpsAPW4pkThReDAVp3QxvUKrkBM8/uWRF3wpaUoPsAHm1dbcL9aiW3lqlLMZjDEwDfU6lxLcPg9d14fq4dc44FvPx6aYcymkgJoYvR6P1wECpxqlEAR2K1cvMtqCqvVESBQV/EUtWiALNuwR2PbhwtBWJd+e8BdFI7OLkit4uYYux6Yu35uyGQ==
Status: connect
Changed: 2017-07-17T17:04:03+02:00

[Tech-C]
Type: ROLE
Name: DENIC Business Services
Organisation: DENIC eG
Address: Kaiserstraße 75 - 77
PostalCode: 60329
City: Frankfurt am Main
CountryCode: DE
Phone: +49 69 27235 272
Fax: +49 69 27235 234
Email: dbs@denic.de
Remarks: Information: https://www.denic.de
Changed: 2017-01-03T13:20:51+01:00

[Zone-C]
Type: ROLE
Name: DENIC Business Services
Organisation: DENIC eG
Address: Kaiserstraße 75 - 77
PostalCode: 60329
City: Frankfurt am Main
CountryCode: DE
Phone: +49 69 27235 272
Fax: +49 69 27235 234
Email: dbs@denic.de
Remarks: Information: https://www.denic.de
Changed: 2017-01-03T13:20:51+01:00`)

	mustTime := func(in time.Time, err error) time.Time {
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		return in
	}

	p := parser.DENICMapping()(parser.ParseDENICDomainRecord)
	rec, err := p(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	st.Expect(t, rec.DomainRecord.DomainName, "denic.de")
	st.Assert(t, rec.DomainRecord.NameServers, []string{
		"ns1.denic.de",
		"ns2.denic.de",
		"ns3.denic.de",
	})
	st.Expect(t, rec.DomainRecord.Updated, mustTime(time.Parse("2006-01-02T15:04:05-07:00", "2017-07-17T17:04:03+02:00")))
	st.Expect(t, rec.DomainRecord.DomainStatus, parser.StatusOK)

	st.Expect(t, rec.DomainRecord.Tech.Name, "DENIC Business Services")
	st.Expect(t, rec.DomainRecord.Tech.Organization, "DENIC eG")
	st.Expect(t, rec.DomainRecord.Tech.Street, "Kaiserstraße 75 - 77")
	st.Expect(t, rec.DomainRecord.Tech.PostalCode, "60329")
	st.Expect(t, rec.DomainRecord.Tech.City, "Frankfurt am Main")
	st.Expect(t, rec.DomainRecord.Tech.Country, "DE")
	st.Expect(t, rec.DomainRecord.Tech.Phone, "+49 69 27235 272")
	st.Expect(t, rec.DomainRecord.Tech.Fax, "+49 69 27235 234")
	st.Expect(t, rec.DomainRecord.Tech.Email, "dbs@denic.de")
	st.Expect(t, rec.DomainRecord.Tech.Remarks, "Information: https://www.denic.de")
	st.Expect(t, rec.DomainRecord.Tech.Updated, mustTime(time.Parse("2006-01-02T15:04:05-07:00", "2017-01-03T13:20:51+01:00")))
}

func TestParseDENICDomainRecord_err(t *testing.T) {
	r := strings.NewReader(`Domain: not-exists.de
Status: free`)
	p := parser.DENICMapping()(parser.ParseDENICDomainRecord)
	_, err := p(r)
	if err == nil {
		t.Errorf("expecting error but got nil")
		return
	}
	st.Expect(t, err, parser.ErrorDomainNotFound)
}
