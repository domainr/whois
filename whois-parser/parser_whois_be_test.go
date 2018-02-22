package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nbio/st"

	parser "github.com/domainr/whois/whois-parser"
)

func TestParseBeDomainRecord(t *testing.T) {
	r := strings.NewReader(`% .be Whois Server 6.1
%
% The WHOIS service offered by DNS Belgium and the access to the records in the DNS Belgium
% WHOIS database are provided for information purposes only. It allows
% persons to check whether a specific domain name is still available or not
% and to obtain information related to the registration records of
% existing domain names.
%
% DNS Belgium cannot, under any circumstances, be held liable where the stored
% information would prove to be incomplete or inaccurate in any sense.
%
% By submitting a query you agree not to use the information made available
% to:
%   - allow, enable or otherwise support the transmission of unsolicited,
%     commercial advertising or other solicitations whether via email or otherwise;
%   - target advertising in any possible way;
%   - to cause nuisance in any possible way to the domain name holders by sending
%     messages to them (whether by automated, electronic processes capable of
%     enabling high volumes or other possible means).
%
% Without prejudice to the above, it is explicitly forbidden to extract, copy
% and/or use or re-utilise in any form and by any means (electronically or
% not) the whole or a quantitatively or qualitatively substantial part
% of the contents of the WHOIS database without prior and explicit permission
% by DNS Belgium, nor in any attempt thereof, to apply automated, electronic
% processes to DNS Belgium (or its systems).
%
% You agree that any reproduction and/or transmission of data for commercial
% purposes will always be considered as the extraction of a substantial
% part of the content of the WHOIS database.
%
% By submitting the query you agree to abide by this policy and accept that
% DNS Belgium can take measures to limit the use of its whois services in order to
% protect the privacy of its registrants or the integrity of the database.
%

Domain:	dns.be
Status:	NOT AVAILABLE
Registered:	Mon Jan 1 1996

Registrant:
	Not shown, please visit www.dnsbelgium.be for webbased whois.

Registrar Technical Contacts:
	Name:	DNS BE Technical Staff
	Organisation:	DNS Belgium vzw
	Language:	en
	Phone:	+32.16284970
	Fax:	+32.16284971
	Email:	iana-tech@dnsbelgium.be


Registrar:
	Name:	 DNS BE vzw/asbl
	Website: http://www.dns.be

Nameservers:
	c.ns.dns.be (194.0.43.1)
	c.ns.dns.be (2001:678:68:0:0:0:0:1)
	d.ns.dns.be (194.0.44.1)
	a.ns.dns.be (194.0.6.1)
	x.ns.dns.be (194.0.1.10)
	x.ns.dns.be (2001:678:4:0:0:0:0:a)
	a.ns.dns.be (2001:678:9:0:0:0:0:1)
	b.ns.dns.be (194.0.37.1)
	b.ns.dns.be (2001:678:64:0:0:0:0:1)
	d.ns.dns.be (2001:678:6c:0:0:0:0:1)
	y.ns.dns.be (2001:dcd:7:0:0:0:0:8)
	y.ns.dns.be (120.29.253.8)

Keys:
	keyTag:64156 flags:KSK protocol:3 algorithm:RSA-SHA256 pubKey:AwEAAcUMaeEPrigxGE1niu6Z3jZFL4DmPWYHAXpmOP1tTQhx7y+6gyhxe3Od3qQgnWwSZeEkMdLkaPtnu93Etvom1Sjum859LjSg/z+AomNT//xMyTe23RPINOV7dWuq35Z5v3LeTZ1q4cgtexpNk++iHW6weATPmex/J7KNbhbmhWrOrv7Z6HG5CdQOLlF+ezUIr+dBHzdwj7ZD/gOTV/SI0etjf8MO6tLH/FHT919SMdZ8pfgOD3rMnrVRKT8/N7kd9p6j9FSxDMdcvxjx9U9czuYiM4tiJYvnFwgsy+RlTD4S6qVj3i6xKztzyhkEE1oPbglWjMDF3m4El8UsvIWW1Jk=

Flags:
	clientTransferProhibited
	serverTransferProhibited

Please visit www.dnsbelgium.be for more info.`)

	mustTime := func(in time.Time, err error) time.Time {
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		return in
	}

	p := parser.BeMapping()(parser.ParseBeDomainRecord)
	rec, err := p(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if rec.DomainRecord == nil {
		t.Errorf("rec.DomainRecord is nil")
	}
	st.Expect(
		t,
		rec.DomainRecord.NameServers,
		[]string{
			"c.ns.dns.be",
			"c.ns.dns.be",
			"d.ns.dns.be",
			"a.ns.dns.be",
			"x.ns.dns.be",
			"x.ns.dns.be",
			"a.ns.dns.be",
			"b.ns.dns.be",
			"b.ns.dns.be",
			"d.ns.dns.be",
			"y.ns.dns.be",
			"y.ns.dns.be",
		},
	)
	st.Expect(t, rec.DomainRecord.DomainName, "dns.be")
	st.Expect(t, rec.DomainRecord.Created, mustTime(time.Parse("Mon Jan 2 2006 MST", "Mon Jan 1 1996 CET")))
	st.Expect(t, rec.DomainRecord.Registrar.Name, "DNS BE vzw/asbl")
	st.Expect(t, rec.DomainRecord.Registrar.Organization, "DNS Belgium vzw")
	st.Expect(t, rec.DomainRecord.Registrar.Phone, "+32.16284970")
	st.Expect(t, rec.DomainRecord.Registrar.Fax, "+32.16284971")
	st.Expect(t, rec.DomainRecord.Registrar.Email, "iana-tech@dnsbelgium.be")
}
