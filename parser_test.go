/*
 * Copyright 2014-2024 Li Kexian
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
			"hm", "int", "name", "nl", "nz", "tk", "kz", "hu"}, extension) {
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
