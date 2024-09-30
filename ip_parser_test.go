package whoisparser

import (
	"testing"

	"github.com/likexian/gokit/assert"
)

func TestParseIPWhois(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected WhoisInfo
	}{
		{
			name: "Valid IP WHOIS",
			input: `
NetRange:       99.10.64.0 - 99.75.191.255
CIDR:           99.74.0.0/16, 99.75.0.0/17, 99.72.0.0/15, 99.16.0.0/12, 99.11.0.0/16, 99.64.0.0/13, 99.32.0.0/11, 99.75.128.0/18, 99.10.128.0/17, 99.12.0.0/14, 99.10.64.0/18
NetName:        SBCIS-SBIS
NetHandle:      NET-99-10-64-0-1
Parent:         NET99 (NET-99-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS7132
Organization:   AT&T Corp. (AC-3280)
RegDate:        2008-02-25
Updated:        2018-07-19
Ref:            https://rdap.arin.net/registry/ip/99.10.64.0
`,
			expected: WhoisInfo{
				IP: &IPInfo{
					NetRange:     "99.10.64.0 - 99.75.191.255",
					CIDR:         []string{"99.74.0.0/16", "99.75.0.0/17", "99.72.0.0/15", "99.16.0.0/12", "99.11.0.0/16", "99.64.0.0/13", "99.32.0.0/11", "99.75.128.0/18", "99.10.128.0/17", "99.12.0.0/14", "99.10.64.0/18"},
					NetName:      "SBCIS-SBIS",
					NetHandle:    "NET-99-10-64-0-1",
					Parent:       "NET99 (NET-99-0-0-0-0)",
					NetType:      "Direct Allocation",
					OriginAS:     "AS7132",
					Organization: "AT&T Corp. (AC-3280)",
					RegDate:      "2008-02-25",
					Updated:      "2018-07-19",
					Ref:          "https://rdap.arin.net/registry/ip/99.10.64.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			assert.Nil(t, err)
			assert.Equal(t, tt.expected.IP, result.IP)
		})
	}
}

func TestIsIPWhois(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "IP WHOIS",
			input:    "NetRange: 192.168.0.0 - 192.168.255.255\nCIDR: 192.168.0.0/16",
			expected: true,
		},
		{
			name:     "Domain WHOIS",
			input:    "Domain Name: example.com\nRegistrar: Example Registrar, LLC",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPWhois(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
