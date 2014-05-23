package tools

type ZoneWhois struct {
	Zone   string
	Server string
	Msg    string
	ViaDNS bool
}

var Exceptions = map[string]ZoneWhois{
	"bd":               ZoneWhois{Server: "www.whois.com.bd", Msg: "http://www.whois.com.bd/"},
	"bv":               ZoneWhois{Server: "whois.norid.no", Msg: "http://www.norid.no/navnepolitikk.en.html#link1"},
	"gmo":              ZoneWhois{Server: "whois.gmoregistry.net", Msg: "http://en.wikipedia.org/wiki/.gmo"},
	"lk":               ZoneWhois{Server: "whois.nic.lk", Msg: "http://nic.lk"},
	"nr":               ZoneWhois{Server: "cenpac.net.nr", Msg: "http://cenpac.net.nr/dns/"},
	"sj":               ZoneWhois{Server: "whois.norid.no", Msg: "http://www.norid.no/navnepolitikk.en.html#link1"},
	"va":               ZoneWhois{Server: "whois.iana.org", Msg: "Every .va domain name owned by the Vatican"},
	"xn--90a3ac":       ZoneWhois{Server: "whois.rnids.rs", Msg: "http://en.wikipedia.org/wiki/.xn--90a3ac"},
	"xn--fzc2c9e2c":    ZoneWhois{Server: "whois.nic.lk", Msg: "http://www.iana.org/domains/root/db/.xn--fzc2c9e2c.html"},
	"xn--mgbc0a9azcg":  ZoneWhois{Server: "whois.iam.net.ma", Msg: "Morocco"},
	"xn--pgbs0dh":      ZoneWhois{Server: "whois.ati.tn", Msg: "Tunisia"},
	"xn--rhqv96g":      ZoneWhois{Server: "whois.nic.xn--rhqv96g", Msg: "China"},
	"xn--ses554g":      ZoneWhois{Server: "whois.gtld.knet.cn", Msg: "China: whois -h whois.gtld.knet.cn nic.xn--ses554g"},
	"xn--xkc2al3hye2a": ZoneWhois{Server: "whois.nic.lk", Msg: "Sri Lanka"},
	"za":               ZoneWhois{Server: "whois.registry.net.za", Msg: "http://en.wikipedia.org/wiki/.za"},
}
