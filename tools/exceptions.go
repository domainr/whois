package tools

type Exception struct {
	Server string
	Msg    string
}

var Exceptions = map[string]Exception{
	"bd":               Exception{"www.whois.com.bd", "http://www.whois.com.bd/"},
	"bv":               Exception{"whois.norid.no", "http://www.norid.no/navnepolitikk.en.html#link1"},
	"gmo":              Exception{"whois.gmoregistry.net", "http://en.wikipedia.org/wiki/.gmo"},
	"lk":               Exception{"whois.nic.lk", "http://nic.lk"},
	"nr":               Exception{"cenpac.net.nr", "http://cenpac.net.nr/dns/"},
	"sj":               Exception{"whois.norid.no", "http://www.norid.no/navnepolitikk.en.html#link1"},
	"va":               Exception{"whois.iana.org", "Every .va domain name owned by the Vatican"},
	"xn--90a3ac":       Exception{"whois.rnids.rs", "http://en.wikipedia.org/wiki/.xn--90a3ac"},
	"xn--fzc2c9e2c":    Exception{"whois.nic.lk", "http://www.iana.org/domains/root/db/.xn--fzc2c9e2c.html"},
	"xn--mgbc0a9azcg":  Exception{"whois.iam.net.ma", "Morocco"},
	"xn--pgbs0dh":      Exception{"whois.ati.tn", "Tunisia"},
	"xn--rhqv96g":      Exception{"whois.nic.xn--rhqv96g", "China"},
	"xn--ses554g":      Exception{"whois.gtld.knet.cn", "China: whois -h whois.gtld.knet.cn nic.xn--ses554g"},
	"xn--xkc2al3hye2a": Exception{"whois.nic.lk", "Sri Lanka"},
	"za":               Exception{"whois.registry.net.za", "http://en.wikipedia.org/wiki/.za"},
}
