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

func TestClientReadLimit(t *testing.T) {
	tests := []struct {
		name      string
		readLimit int64
		want      int64
	}{
		{"zero uses default", 0, DefaultReadLimit},
		{"negative uses default", -1, DefaultReadLimit},
		{"custom value", 2 << 20, 2 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{ReadLimit: tt.readLimit}
			if got := c.readLimit(); got != tt.want {
				t.Errorf("readLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}
