package whois

import (
	"testing"

	"github.com/zonedb/zonedb"
)

func TestServer(t *testing.T) {
	tests := []struct {
		domain     string
		wantServer string
		wantURL    string
		wantErr    bool
	}{
		{"example.fake-domain", "", "", true},
		{"example.com", "whois.verisign-grs.com", "", false},
		{"example.nr", "www.cenpac.net.nr", "http://www.cenpac.net.nr/dns/whois.html", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			z := zonedb.PublicZone(tt.domain)
			if z == nil {
				if !tt.wantErr {
					t.Errorf("%v shouldn’t exist", tt.domain)
				}
				return
			}
			gotServer, gotURL, err := Server(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Server() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotServer != tt.wantServer {
				t.Errorf("Server() server = %v, want %v", gotServer, tt.wantServer)
			}
			if gotURL != tt.wantURL {
				t.Errorf("Server() URL = %v, want %v", gotURL, tt.wantURL)
			}
		})
	}
}
