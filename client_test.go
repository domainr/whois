package whois

import (
	"reflect"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    *Client
	}{
		{"zero timeout", 0, &Client{}},
		{"positive timeout", 1 * time.Second, &Client{Timeout: 1 * time.Second}},
		{"negative timeout", -1 * time.Second, &Client{Timeout: -1 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewClient(tt.timeout); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewClient() = %v, want %v", got, tt.want)
			}
		})
	}
}
