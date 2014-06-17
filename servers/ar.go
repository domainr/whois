package servers

import (
	"net/url"
	"strings"

	"github.com/domainr/go-whois/whois"
)

var slds = map[string]string{
	"com.ar": "2",
	"gob.ar": "3",
	"int.ar": "4",
	"mil.ar": "5",
	"net.ar": "6",
	"org.ar": "7",
	"tur.ar": "8",
}

var ar = &whois.Server{
	Resolve: func(req *whois.Request) error {
		labels := strings.SplitN(req.Query, ".", 2)
		values := url.Values{}
		values.Set("busquedaDominioForm2", "busquedaDominioForm2")
		values.Set("javax.faces.ViewState", "6589297412437530687:-5437376346305596100")
		values.Set("busquedaDominioForm2:dominio", labels[0])
		values.Set("busquedaDominioForm2:j_idt56", slds[labels[1]])
		req.URL = "https://nic.ar/buscarDominio.xhtml"
		req.Body = values.Encode()
		return nil
	},
}

func init() {
	whois.RegisterServer(
		ar,
		"nic.ar",
	)
}
