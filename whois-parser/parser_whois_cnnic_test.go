package parser_test

import (
	"io"
	"strings"
	"testing"
	"time"

	parser "github.com/domainr/whois/whois-parser"
	"github.com/nbio/st"
)

func TestParseCNNICDomainRecord_normal(t *testing.T) {
	r := strings.NewReader(`Domain Name: cnnic.cn
ROID: 20030310s10001s00012956-cn
Domain Status: serverDeleteProhibited
Domain Status: serverUpdateProhibited
Domain Status: serverTransferProhibited
Registrant ID: s1255673574881
Registrant: 中国互联网络信息中心
Registrant Contact Email: servicei@cnnic.cn
Sponsoring Registrar: 北京新网数码信息技术有限公司
Name Server: a.cnnic.cn
Name Server: b.cnnic.cn
Name Server: c.cnnic.cn
Name Server: d.cnnic.cn
Name Server: e.cnnic.cn
Registration Time: 2003-03-10 19:06:34
Expiration Time: 2019-03-10 19:06:34
DNSSEC: unsigned`)

	mustTime := func(in time.Time, err error) time.Time {
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		return in
	}

	p := parser.CNNICMapping()(parser.ParseCNNICDomainRecord)
	rec, err := p(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if rec.DomainRecord == nil {
		t.Errorf("rec.DomainRecord is nil")
	}

	st.Expect(t, rec.DomainRecord.DomainName, "cnnic.cn")
	st.Expect(t, rec.DomainRecord.RegistryID, "20030310s10001s00012956-cn")
	st.Expect(
		t,
		rec.DomainRecord.DomainStatus,
		parser.StatusServerDeleteProhibited|
			parser.StatusServerUpdateProhibited|
			parser.StatusServerTransferProhibited,
	)
	st.Expect(t, rec.DomainRecord.Registrant.RegistryID, "s1255673574881")
	st.Expect(t, rec.DomainRecord.Registrant.Name, "中国互联网络信息中心")
	st.Expect(t, rec.DomainRecord.Registrant.Email, "servicei@cnnic.cn")
	st.Assert(t, rec.DomainRecord.NameServers, []string{
		"a.cnnic.cn",
		"b.cnnic.cn",
		"c.cnnic.cn",
		"d.cnnic.cn",
		"e.cnnic.cn",
	})
	st.Expect(t, rec.DomainRecord.Created, mustTime(time.Parse("2006-01-02 15:04:05", "2003-03-10 19:06:34")))
	st.Expect(t, rec.DomainRecord.Expires, mustTime(time.Parse("2006-01-02 15:04:05", "2019-03-10 19:06:34")))
	st.Expect(t, rec.DomainRecord.DNSSEC, parser.DNSSECUnsigned)
}

func TestParseCNNICDomainRecord_err(t *testing.T) {
	var r io.Reader
	var p parser.Parser
	var err error

	r = strings.NewReader(`the Domain Name you apply can not be registered online. Please consult your Domain Name registrar`)
	p = parser.CNNICMapping()(parser.ParseCNNICDomainRecord)
	_, err = p(r)
	st.Expect(t, err, parser.ErrorDomainReserved)

	r = strings.NewReader(`the domain you want to register is reserved.`)
	p = parser.CNNICMapping()(parser.ParseCNNICDomainRecord)
	_, err = p(r)
	st.Expect(t, err, parser.ErrorDomainReserved)

	r = strings.NewReader(`no matching record.`)
	p = parser.CNNICMapping()(parser.ParseCNNICDomainRecord)
	_, err = p(r)
	st.Expect(t, err, parser.ErrorDomainNotFound)
}
