/*
 * Copyright 2014-2020 Li Kexian
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
 * Go module for domain whois info parse
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
)

const (
	VERIFIEDLIST = `
# whois-parser.go

## Overview

It is supposed to be working with all domain extensions, but verified extensions as below must works, because I have checked them one by one manually.

If there is any problems, please feel free to open a new issue.

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

func TestWhoisParser(t *testing.T) {
	exts := []string{}
	domains := map[string][]string{}

	_, err := Parse("not found")
	assert.Equal(t, err, ErrDomainNotFound)

	_, err = Parse("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
	assert.Equal(t, err, ErrDomainLimitExceed)

	_, err = Parse("Hello - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
	assert.Equal(t, err, ErrDomainInvalidData)

	dirs, err := xfile.ListDir("./examples/", xfile.TypeFile, -1)
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

		whoisRaw, err := xfile.ReadText("./examples/" + v.Name)
		assert.Nil(t, err)

		whoisInfo, err := Parse(whoisRaw)
		assert.Nil(t, err)

		assert.Equal(t, strings.ToLower(whoisInfo.Domain.Domain), domain)
		assert.Equal(t, strings.ToLower(whoisInfo.Domain.Extension), extension)

		if !assert.IsContains([]string{"", "aq", "br", "ch", "de", "edu", "eu", "fr", "gov", "hk",
			"hm", "int", "it", "jp", "kr", "mo", "nl", "nz", "pm", "re", "ro", "ru", "su", "tf",
			"tk", "travel", "tv", "tw", "uk", "wf", "yt", "ir", "fi"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.ID)
		}

		if !assert.IsContains([]string{"ch", "edu", "eu", "int", "kr", "mo", "tw", "ir", "tk"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.Status)
		}

		if assert.IsContains([]string{"git.nl", "git.wf", "switch.ch", "git.xyz"}, domain) {
			assert.True(t, whoisInfo.Domain.DnsSec)
		} else {
			assert.False(t, whoisInfo.Domain.DnsSec)
		}

		if !assert.IsContains([]string{"aero", "aq", "asia", "berlin", "biz", "br", "ch", "cn",
			"co", "cymru", "de", "edu", "eu", "fr", "gov", "hk", "hm", "in", "int", "it", "jp", "kr",
			"la", "london", "me", "mo", "museum", "name", "nl", "nz", "pm", "re", "ro", "ru", "sh",
			"su", "tel", "tf", "tk", "travel", "tw", "uk", "us", "wales", "wf", "xxx", "yt", "ir", "fi"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.WhoisServer)
		}

		if !assert.IsContains([]string{"gov", "name", "tw"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.NameServers)
		}

		if !assert.IsContains([]string{"aq", "au", "de", "eu", "gov", "hm", "name", "nl", "nz", "ir", "tk"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.CreatedDate)
		}

		if !assert.IsContains([]string{"aq", "ch", "cn", "eu", "gov", "hk", "hm", "mo",
			"name", "nl", "ro", "ru", "su", "tk", "tw"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.UpdatedDate)
		}

		if !assert.IsContains([]string{"", "aq", "au", "br", "ch", "de", "eu", "gov",
			"hm", "int", "name", "nl", "nz", "tk"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.ExpirationDate)
		}

		if !assert.IsContains([]string{"", "ai", "aq", "au", "br", "ca", "ch", "cn", "cx", "de",
			"edu", "eu", "fr", "gov", "gs", "hk", "hm", "int", "it", "jp", "kr", "la", "mo", "nl",
			"nz", "pm", "re", "ro", "ru", "su", "tf", "tk", "tw", "uk", "wf", "yt", "ir", "fi"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.ID)
		}

		if !assert.IsContains([]string{"", "aq", "br", "de",
			"edu", "gov", "hm", "int", "jp", "mo", "tk", "ir"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.Name)
		}

		if !assert.IsContains([]string{"", "aero", "ai", "aq", "asia", "au", "br", "ch", "cn", "de",
			"edu", "gov", "hk", "hm", "int", "jp", "kr", "la", "london", "love", "mo",
			"museum", "name", "nl", "nz", "ru", "su", "tk", "top", "ir", "fi"}, extension) {
			assert.NotZero(t, whoisInfo.Registrar.ReferralURL)
		}

		err = xjson.Dump("./examples/"+v.Name+".json", whoisInfo)
		assert.Nil(t, err)

		if !assert.IsContains(exts, extension) {
			exts = append(exts, extension)
		}

		if _, ok := domains[extension]; !ok {
			domains[extension] = []string{}
		}

		domains[extension] = append(domains[extension], strings.ToLower(whoisInfo.Domain.Domain))
	}

	sort.Strings(exts)
	verified := VERIFIEDLIST

	for _, k := range exts {
		sort.Strings(domains[k])
		for _, vv := range domains[k] {
			kk := k
			if kk == "" {
				kk = vv
			}
			verified += fmt.Sprintf("| .%s | [%s](%s_%s) | [%s](%s_%s.json) | √ |\n",
				k, vv, kk, vv, vv, kk, vv)
		}
	}

	err = xfile.WriteText("./examples/README.md", strings.TrimSpace(verified))
	assert.Nil(t, err)
}
