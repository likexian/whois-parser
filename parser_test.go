/*
 * Copyright 2014-2026 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xfile"
	"github.com/likexian/gokit/xjson"
	"golang.org/x/net/idna"
)

const (
	noterrorDir  = "testdata/noterror"
	notfoundDir  = "testdata/notfound"
	verifiedList = `
# WhoisParser

## Overview

It is supposed to be working with all domain extensions,

but verified extensions as below must works, because I have checked them one by one manually.

If there is any problem, please feel free to open a new issue.

## Verified Extensions

| extension | whois | output | verified |
| --------- | ----- | ------ | :------: |
`
)

func TestVersion(t *testing.T) {
	assert.Contains(t, Version(), ".")
	assert.Contains(t, Author(), "likexian")
	assert.Contains(t, License(), "Apache License")
}

func TestParseError(t *testing.T) {
	tests := map[error]string{
		ErrNotFoundDomain:    "No matching record.",
		ErrReservedDomain:    "Reserved Domain Name",
		ErrPremiumDomain:     "This platinum domain is available for purchase.",
		ErrBlockedDomain:     "This name subscribes to the Uni EPS+ product",
		ErrDomainDataInvalid: "connect to whois server failed: dial tcp 43: i/o timeout",
		ErrDomainLimitExceed: "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS",
	}

	for e, v := range tests {
		_, err := Parse(v)
		assert.Equal(t, err, e)
	}

	_, err := Parse(`Domain Name: likexian-no-money-registe.ai
	Domain Status: No Object Found`)
	assert.Equal(t, err, ErrNotFoundDomain)
}

func TestParse(t *testing.T) {
	extensions := []string{}
	domains := map[string][]string{}

	dirs, err := xfile.ListDir(noterrorDir, xfile.TypeFile, -1)
	assert.Nil(t, err)

	for _, v := range dirs {
		if v.Name == "README.md" {
			continue
		}

		domain := strings.Split(v.Name, "_")[1]
		extension := ""
		if strings.Contains(v.Name, ".") {
			extension = domain[strings.LastIndex(domain, ".")+1:]
		}

		if assert.IsContains([]string{"pre", "json"}, extension) {
			continue
		}

		whoisRaw, err := xfile.ReadText(noterrorDir + "/" + v.Name)
		assert.Nil(t, err)

		whoisInfo, err := Parse(whoisRaw)
		assert.Nil(t, err, v.Name)

		assert.Equal(t, whoisInfo.Domain.Punycode, domain)
		assert.Equal(t, whoisInfo.Domain.Extension, extension)

		if !assert.IsContains([]string{"", "at", "aq", "br", "ch", "de", "edu", "eu", "fr", "gg", "gov", "hk",
			"hm", "int", "it", "jp", "kr", "kz", "mo", "nl", "nz", "pl", "pm", "re", "ro", "ru", "su", "tf", "ee",
			"tk", "travel", "tv", "tw", "uk", "wf", "yt", "ir", "fi", "rs", "dk", "by", "ua",
			"xn--mgba3a4f16a", "xn--p1ai", "se", "sk", "nu", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.ID)
		}

		if !assert.IsContains([]string{"at", "ch", "edu", "eu", "int", "kr", "mo", "tw", "ir", "pl", "tk", "by",
			"xn--mgba3a4f16a", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.Status)
		}

		if assert.IsContains([]string{"aftermarket.pl", "nazwa.pl", "git.nl", "git.wf", "by",
			"switch.ch", "git.xyz", "emilstahl.dk", "folketinget.dk", "nic.nu", "xn--fl-fka.se"}, domain) {
			assert.True(t, whoisInfo.Domain.DNSSec)
		} else {
			assert.False(t, whoisInfo.Domain.DNSSec)
		}

		if !assert.IsContains([]string{"aero", "ai", "at", "aq", "asia", "berlin", "biz", "br", "ch", "cn",
			"co", "cymru", "de", "edu", "eu", "fr", "gg", "gov", "hk", "hm", "in", "int", "it", "jp", "kr",
			"la", "london", "me", "mo", "museum", "name", "nl", "nz", "pm", "re", "ro", "ru", "sh", "sk",
			"kz", "su", "tel", "ee", "tf", "tk", "travel", "tw", "uk", "us", "wales", "wf", "xxx",
			"yt", "ir", "fi", "rs", "dk", "by", "ua", "xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai",
			"se", "nu", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.WhoisServer)
		}

		if !assert.IsContains([]string{"gov", "name", "tw", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.NameServers)
		}

		if !assert.IsContains([]string{"aq", "ai", "at", "au", "de", "eu", "gov", "hm", "name", "nl", "nz", "ir", "tk",
			"xn--mgba3a4f16a"}, extension) &&
			!strings.Contains(domain, "ac.jp") &&
			!strings.Contains(domain, "co.jp") &&
			!strings.Contains(domain, "go.jp") &&
			!strings.Contains(domain, "ne.jp") {
			assert.NotZero(t, whoisInfo.Domain.CreatedDate)
			assert.NotNil(t, whoisInfo.Domain.CreatedDateInTime)
		}

		if !assert.IsContains([]string{"aq", "ai", "at", "ch", "cn", "eu", "gg", "gov", "hk", "hm", "mo",
			"name", "nl", "ro", "ru", "su", "tk", "tw", "dk", "xn--fiqs8s", "xn--p1ai", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.UpdatedDate)
			assert.NotNil(t, whoisInfo.Domain.UpdatedDateInTime)
		}

		if !assert.IsContains([]string{"", "ai", "at", "aq", "au", "br", "ch", "de", "eu", "gg", "gov", "ee",
			"hm", "int", "name", "nl", "nz", "tk", "kz", "hu"}, extension) &&
			!strings.Contains(domain, "ac.jp") &&
			!strings.Contains(domain, "co.jp") &&
			!strings.Contains(domain, "go.jp") &&
			!strings.Contains(domain, "ne.jp") {
			assert.NotZero(t, whoisInfo.Domain.ExpirationDate)
			assert.NotNil(t, whoisInfo.Domain.ExpirationDateInTime)
		}

		if !assert.IsContains([]string{"", "ai", "at", "aq", "au", "br", "ca", "ch", "cn", "cx", "de",
			"edu", "eu", "fr", "gg", "gov", "gs", "hk", "hm", "int", "it", "jp", "kr", "kz", "la", "mo", "nl",
			"nz", "pl", "pm", "re", "ro", "ru", "su", "sk", "tf", "tk", "tw", "uk", "wf", "yt", "ir", "fi", "rs",
			"ee", "dk", "by", "ua", "xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai", "se", "nu", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.ID)
		}

		if !assert.IsContains([]string{"", "at", "aq", "br", "de",
			"edu", "gov", "hm", "int", "jp", "mo", "tk", "ir", "dk", "xn--mgba3a4f16a", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.Name)
		}

		if !assert.IsContains([]string{"", "aero", "ai", "at", "aq", "asia", "au", "br", "ch", "cn", "de",
			"edu", "gov", "hk", "hm", "int", "jp", "kr", "kz", "la", "london", "love", "mo",
			"museum", "name", "nl", "nz", "pl", "ru", "sk", "su", "tk", "top", "ir", "fi", "rs", "dk", "by", "ua",
			"xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai", "se", "nu", "hu"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.ReferralURL)
		}

		err = xjson.Dump(noterrorDir+"/"+v.Name+".json", whoisInfo)
		assert.Nil(t, err)

		extension, _ = idna.ToUnicode(extension)
		if !assert.IsContains(extensions, extension) {
			extensions = append(extensions, extension)
		}

		if _, ok := domains[extension]; !ok {
			domains[extension] = []string{}
		}

		domains[extension] = append(domains[extension], domain)
	}

	sort.Strings(extensions)
	verified := verifiedList

	for _, extension := range extensions {
		sort.Strings(domains[extension])
		for _, domain := range domains[extension] {
			unicodeDomain, _ := idna.ToUnicode(domain)
			asciiExtension, _ := idna.ToASCII(extension)
			if asciiExtension == "" {
				asciiExtension = domain
			}
			verified += fmt.Sprintf("| .%s | [%s](%s_%s) | [%s](%s_%s.json) | √ |\n",
				extension, unicodeDomain, asciiExtension, domain, unicodeDomain, asciiExtension, domain)
		}
	}

	err = xfile.WriteText(noterrorDir+"/README.md", strings.TrimSpace(verified))
	assert.Nil(t, err)
}

func TestAssearchDomain(t *testing.T) {
	tests := []struct {
		whois     string
		name      string
		extension string
	}{
		{"Domain: example.com\n", "example", "com"},
		{"Domain Name: example.com\n", "example", "com"},
		{"Domain_Name: example.com\n", "example", "com"},

		{"Domain: com\n", "com", ""},
		{"Domain Name: com\n", "com", ""},
		{"Domain_Name: com\n", "com", ""},

		{"Domain Name: 示例.中国\n", "示例", "中国"},
		{"Domain Name: 中国\n", "中国", ""},
	}

	for _, v := range tests {
		name, extension := searchDomain(v.whois)
		assert.Equal(t, name, v.name)
		assert.Equal(t, extension, v.extension)
	}
}

func TestParseCZGlueRecords(t *testing.T) {
	whoisRaw := `%  (c) 2006-2021 CZ.NIC, z.s.p.o.
% 
% Intended use of supplied data and information
% 
% Data contained in the domain name register, as well as information
% supplied through public information services of CZ.NIC association,
% are appointed only for purposes connected with Internet network
% administration and operation, or for the purpose of legal or other
% similar proceedings, in process as regards a matter connected
% particularly with holding and using a concrete domain name.
% 
% Full text available at:
% http://www.nic.cz/page/306/intended-use-of-supplied-data-and-information/
% 
% See also a search service at http://www.nic.cz/whois/
% 
% 
% Whoisd Server Version: 3.15.0
% Timestamp: Sat Oct 10 22:14:35 2026

domain:       nic.cz
registrant:   CZ-NIC
admin-c:      FEELA
admin-c:      MAPET
nsset:        CZ.NIC
keyset:       AUTO-ZHHWRIDCGH9F46ZDG2K2VC284
registrar:    REG-CZNIC
status:       Sponsoring registrar change forbidden
registered:   30.10.1997 01:00:00
changed:      17.11.2020 14:25:52
expire:       15.03.2027

contact:      CZ-NIC
org:          CZ.NIC, z.s.p.o.
name:         CZ.NIC, z.s.p.o.
address:      Milesovska 1136/5
address:      Praha 3
address:      130 00
address:      CZ
registrar:    REG-CZNIC
created:      17.10.2008 12:08:21
changed:      15.05.2018 21:32:00

contact:      FEELA
name:         Ondřej Filip
registrar:    REG-MOJEID
created:      04.01.2005 13:35:00
changed:      06.12.2025 15:00:04

contact:      MAPET
name:         Martin Peterka
registrar:    REG-MOJEID
created:      06.03.2002 18:11:00
changed:      07.04.2025 16:33:55

nsset:        CZ.NIC
nserver:      d.ns.nic.cz (193.29.206.1, 2001:678:1::1)
nserver:      a.ns.nic.cz (194.0.12.1, 2001:678:f::1)
nserver:      b.ns.nic.cz (194.0.13.1, 2001:678:10::1)
tech-c:       JTALIR
registrar:    REG-CZNIC
created:      09.06.2008 14:30:16
changed:      11.12.2024 12:23:18

contact:      JTALIR
name:         Jaromír Talíř
registrar:    REG-MOJEID
created:      26.10.2010 10:53:34
changed:      22.01.2025 18:56:06

keyset:       AUTO-ZHHWRIDCGH9F46ZDG2K2VC284
dnskey:       257 3 13 Hpu4xfZJ43G2gen4cJOZ4DFhaXFaMxLPa+dBceqkbdIaqADX9JLHW/CNpPV+GtgAMc2kHgNEJTaSAUhYG41tvQ==
tech-c:       CZNIC-AKM
registrar:    REG-CZNIC
created:      17.11.2020 14:25:52
changed:      26.08.2026 22:12:22

contact:      CZNIC-AKM
org:          CZ.NIC, z.s.p.o.
name:         CZ.NIC, z.s.p.o.
address:      Milesovska 1136/5
address:      Praha 3
address:      13000
address:      CZ
registrar:    REG-CZNIC
created:      12.08.2024 15:02:38
`

	info, err := Parse(whoisRaw)
	assert.Nil(t, err)
	assert.Equal(t, info.Domain.Domain, "nic.cz")
	assert.Equal(t, info.Domain.NameServers, []string{"d.ns.nic.cz", "a.ns.nic.cz", "b.ns.nic.cz"})
	for _, ns := range info.Domain.NameServers {
		assert.False(t, strings.Contains(ns, "("))
		assert.False(t, strings.Contains(ns, ")"))
		assert.False(t, strings.Contains(ns, ":"))
		assert.False(t, strings.Contains(ns, "193."))
		assert.False(t, strings.Contains(ns, "194."))
	}

	edgeCases := []struct {
		raw      string
		expected []string
	}{
		{
			raw:      "domain: test.cz\nnserver: ns1.test.cz (1.2.3.4)\n",
			expected: []string{"ns1.test.cz"},
		},
		{
			raw:      "domain: test.cz\nnserver: ns1.test.cz (2001:db8::1)\n",
			expected: []string{"ns1.test.cz"},
		},
		{
			raw:      "domain: test.cz\nnserver: ns1.test.cz(1.2.3.4, 2001:db8::1)\n",
			expected: []string{"ns1.test.cz"},
		},
		{
			raw:      "domain: test.cz\nnserver: ns1.test.cz (1.2.3.4, 2001:db8::1), ns2.test.cz (5.6.7.8)\n",
			expected: []string{"ns1.test.cz", "ns2.test.cz"},
		},
		{
			raw:      "domain: example.cz\nnserver: ns1.example.cz\nnserver: ns2.example.cz\n",
			expected: []string{"ns1.example.cz", "ns2.example.cz"},
		},
	}

	for _, tt := range edgeCases {
		edgeInfo, edgeErr := Parse(tt.raw)
		assert.Nil(t, edgeErr)
		assert.Equal(t, edgeInfo.Domain.NameServers, tt.expected)
	}
}
