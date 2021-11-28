/*
 * Copyright 2014-2021 Li Kexian
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
		assert.Nil(t, err)

		assert.Equal(t, whoisInfo.Domain.Punycode, domain)
		assert.Equal(t, whoisInfo.Domain.Extension, extension)

		if !assert.IsContains([]string{"", "aq", "br", "ch", "de", "edu", "eu", "fr", "gov", "hk",
			"hm", "int", "it", "jp", "kr", "kz", "mo", "nl", "nz", "pl", "pm", "re", "ro", "ru", "su", "tf", "ee",
			"tk", "travel", "tv", "tw", "uk", "wf", "yt", "ir", "fi", "rs", "xn--mgba3a4f16a", "xn--p1ai"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.ID)
		}

		if !assert.IsContains([]string{"ch", "edu", "eu", "int", "kr", "mo", "tw", "ir", "pl", "tk",
			"xn--mgba3a4f16a"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.Status)
		}

		if assert.IsContains([]string{"aftermarket.pl", "nazwa.pl", "git.nl", "git.wf", "switch.ch", "git.xyz"}, domain) {
			assert.True(t, whoisInfo.Domain.DNSSec)
		} else {
			assert.False(t, whoisInfo.Domain.DNSSec)
		}

		if !assert.IsContains([]string{"aero", "aq", "asia", "berlin", "biz", "br", "ch", "cn",
			"co", "cymru", "de", "edu", "eu", "fr", "gov", "hk", "hm", "in", "int", "it", "jp", "kr",
			"la", "london", "me", "mo", "museum", "name", "nl", "nz", "pm", "re", "ro", "ru", "sh",
			"kz", "su", "tel", "ee", "tf", "tk", "travel", "tw", "uk", "us", "wales", "wf", "xxx", "yt", "ir", "fi", "rs",
			"xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.WhoisServer)
		}

		if !assert.IsContains([]string{"gov", "name", "tw"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.NameServers)
		}

		if !assert.IsContains([]string{"aq", "au", "de", "eu", "gov", "hm", "name", "nl", "nz", "ir", "tk",
			"xn--mgba3a4f16a"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.CreatedDate)
		}

		if !assert.IsContains([]string{"aq", "ch", "cn", "eu", "gov", "hk", "hm", "mo",
			"name", "nl", "ro", "ru", "su", "tk", "tw", "xn--fiqs8s", "xn--p1ai"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.UpdatedDate)
		}

		if !assert.IsContains([]string{"", "aq", "au", "br", "ch", "de", "eu", "gov", "ee",
			"hm", "int", "name", "nl", "nz", "tk", "kz"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.ExpirationDate)
		}

		if !assert.IsContains([]string{"", "ai", "aq", "au", "br", "ca", "ch", "cn", "cx", "de",
			"edu", "eu", "fr", "gov", "gs", "hk", "hm", "int", "it", "jp", "kr", "kz", "la", "mo", "nl",
			"nz", "pl", "pm", "re", "ro", "ru", "su", "tf", "tk", "tw", "uk", "wf", "yt", "ir", "fi", "rs", "ee",
			"xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.ID)
		}

		if !assert.IsContains([]string{"", "aq", "br", "de",
			"edu", "gov", "hm", "int", "jp", "mo", "tk", "ir", "xn--mgba3a4f16a"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.Name)
		}

		if !assert.IsContains([]string{"", "aero", "ai", "aq", "asia", "au", "br", "ch", "cn", "de",
			"edu", "gov", "hk", "hm", "int", "jp", "kr", "kz", "la", "london", "love", "mo",
			"museum", "name", "nl", "nz", "pl", "ru", "su", "tk", "top", "ir", "fi", "rs",
			"xn--mgba3a4f16a", "xn--fiqs8s", "xn--p1ai"}, extension) {
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
