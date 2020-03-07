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

		if assert.IsContains([]string{"pre", "out"}, extension) {
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

		if !assert.IsContains([]string{"", "aq", "br", "de", "edu", "eu", "fr", "gov", "hm", "int",
			"jp", "mo", "name", "pm", "re", "ru", "su", "tf", "tk", "tw", "uk", "wf", "yt", "ir"}, extension) {
			assert.NotZero(t, whoisInfo.Domain.DNSSEC)
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

		content := ""
		content += fmt.Sprintf("\ndomain\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Domain.ID)
		content += fmt.Sprintf("domain: %s\n", whoisInfo.Domain.Domain)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Domain.Name)
		content += fmt.Sprintf("extension: %s\n", whoisInfo.Domain.Extension)
		content += fmt.Sprintf("status: %s\n", whoisInfo.Domain.Status)
		content += fmt.Sprintf("dnssec: %s\n", whoisInfo.Domain.DNSSEC)
		content += fmt.Sprintf("whois_server: %s\n", whoisInfo.Domain.WhoisServer)
		content += fmt.Sprintf("name_servers: %s\n", whoisInfo.Domain.NameServers)
		content += fmt.Sprintf("created_date: %s\n", whoisInfo.Domain.CreatedDate)
		content += fmt.Sprintf("updated_date: %s\n", whoisInfo.Domain.UpdatedDate)
		content += fmt.Sprintf("expiration_date: %s\n", whoisInfo.Domain.ExpirationDate)

		content += fmt.Sprintf("\nregistrar\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Registrar.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Registrar.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Registrar.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Registrar.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Registrar.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Registrar.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Registrar.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Registrar.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Registrar.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Registrar.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Registrar.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Registrar.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Registrar.Email)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Registrar.ReferralURL)

		content += fmt.Sprintf("\nregistrant\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Registrant.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Registrant.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Registrant.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Registrant.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Registrant.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Registrant.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Registrant.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Registrant.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Registrant.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Registrant.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Registrant.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Registrant.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Registrant.Email)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Registrant.ReferralURL)

		content += fmt.Sprintf("\nadministrative\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Administrative.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Administrative.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Administrative.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Administrative.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Administrative.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Administrative.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Administrative.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Administrative.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Administrative.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Administrative.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Administrative.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Administrative.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Administrative.Email)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Administrative.ReferralURL)

		content += fmt.Sprintf("\ntechnical\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Technical.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Technical.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Technical.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Technical.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Technical.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Technical.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Technical.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Technical.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Technical.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Technical.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Technical.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Technical.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Technical.Email)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Technical.ReferralURL)

		content += fmt.Sprintf("\nbilling\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Billing.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Billing.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Billing.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Billing.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Billing.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Billing.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Billing.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Billing.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Billing.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Billing.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Billing.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Billing.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Billing.Email)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Billing.ReferralURL)

		err = xfile.WriteText("./examples/"+v.Name+".out", content)
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
			verified += fmt.Sprintf("| .%s | [%s](%s_%s) | [%s](%s_%s.out) | √ |\n",
				k, vv, kk, vv, vv, kk, vv)
		}
	}

	err = xfile.WriteText("./examples/README.md", strings.TrimSpace(verified))
	assert.Nil(t, err)
}
