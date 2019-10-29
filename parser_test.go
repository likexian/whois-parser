/*
 * Copyright 2014-2019 Li Kexian
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
		fileName := v.Name
		fileExt := fileName[strings.LastIndex(fileName, ".")+1:]
		if fileName == "README.md" {
			continue
		}

		if assert.IsContains([]string{"pre", "out"}, fileExt) {
			continue
		}

		whoisRaw, err := xfile.ReadText("./examples/" + fileName)
		assert.Nil(t, err)

		whoisInfo, err := Parse(whoisRaw)
		assert.Nil(t, err)

		assert.NotZero(t, whoisInfo.Registrar.DomainName)

		if !assert.IsContains([]string{"ai", "aq", "au", "br", "ca", "ch", "cn", "cx", "de",
			"edu", "eu", "fr", "gov", "gs", "hk", "hm", "int", "it", "jp", "kr", "la", "mo", "nl",
			"nz", "pm", "re", "ro", "ru", "su", "tf", "tk", "tw", "uk", "wf", "yt"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.ID)
		}

		if !assert.IsContains([]string{"aq", "br", "de",
			"edu", "gov", "hm", "int", "jp", "mo", "tk"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.Name)
		}

		if !assert.IsContains([]string{"aq", "br", "ch", "de", "edu", "eu", "fr", "gov", "hk",
			"hm", "int", "it", "jp", "kr", "mo", "nl", "nz", "pm", "re", "ro", "ru", "su", "tf",
			"tk", "travel", "tv", "tw", "uk", "wf", "yt"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.DomainId)
		}

		if !assert.IsContains([]string{"aero", "aq", "asia", "berlin", "biz", "br", "ch", "cn",
			"co", "cymru", "de", "edu", "eu", "fr", "gov", "hk", "hm", "in", "int", "it", "jp", "kr",
			"la", "london", "me", "mo", "museum", "name", "nl", "nz", "pm", "re", "ro", "ru", "sh",
			"su", "tel", "tf", "tk", "travel", "tw", "uk", "us", "wales", "wf", "xxx", "yt"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.WhoisServer)
		}

		if !assert.IsContains([]string{"aero", "ai", "aq", "asia", "au", "br", "ch", "cn", "de",
			"edu", "gov", "hk", "hm", "int", "jp", "kr", "la", "london", "love", "mo",
			"museum", "name", "nl", "nz", "ru", "su", "tk", "top"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.ReferralURL)
		}

		if !assert.IsContains([]string{"ch", "edu", "eu", "int", "kr", "mo", "tw"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.DomainStatus)
		}

		if !assert.IsContains([]string{"aq", "au", "de", "eu", "gov", "hm", "name", "nl", "nz"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.CreatedDate)
		}

		if !assert.IsContains([]string{"aq", "ch", "cn", "eu", "gov", "hk", "hm", "mo",
			"name", "nl", "ro", "ru", "su", "tk", "tw"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.UpdatedDate)
		}

		if !assert.IsContains([]string{"aq", "au", "br", "ch", "de", "eu", "gov",
			"hm", "int", "name", "nl", "nz"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.ExpirationDate)
		}

		if !assert.IsContains([]string{"gov", "name", "tw"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.NameServers)
		}

		if !assert.IsContains([]string{"aq", "br", "de", "edu", "eu", "fr", "gov", "hm", "int",
			"jp", "mo", "name", "pm", "re", "ru", "su", "tf", "tk", "tw", "uk", "wf", "yt"}, fileExt) {
			assert.NotZero(t, whoisInfo.Registrar.DomainDNSSEC)
		}

		content := ""
		content += fmt.Sprintf("registrar_id: %s\n", whoisInfo.Registrar.ID)
		content += fmt.Sprintf("registrar_name: %s\n", whoisInfo.Registrar.Name)
		content += fmt.Sprintf("registrar_organization: %s\n", whoisInfo.Registrar.Organization)
		content += fmt.Sprintf("registrar_phone: %s\n", whoisInfo.Registrar.Phone)
		content += fmt.Sprintf("registrar_email: %s\n", whoisInfo.Registrar.Email)
		content += fmt.Sprintf("registrar_reseller: %s\n", whoisInfo.Registrar.Reseller)
		content += fmt.Sprintf("whois_server: %s\n", whoisInfo.Registrar.WhoisServer)
		content += fmt.Sprintf("referral_url: %s\n", whoisInfo.Registrar.ReferralURL)
		content += fmt.Sprintf("domain_id: %s\n", whoisInfo.Registrar.DomainId)
		content += fmt.Sprintf("domain_name: %s\n", whoisInfo.Registrar.DomainName)
		content += fmt.Sprintf("domain_status: %s\n", whoisInfo.Registrar.DomainStatus)
		content += fmt.Sprintf("created_date: %s\n", whoisInfo.Registrar.CreatedDate)
		content += fmt.Sprintf("updated_date: %s\n", whoisInfo.Registrar.UpdatedDate)
		content += fmt.Sprintf("expiration_date: %s\n", whoisInfo.Registrar.ExpirationDate)
		content += fmt.Sprintf("name_servers: %s\n", whoisInfo.Registrar.NameServers)
		content += fmt.Sprintf("domain_dnssec: %s\n", whoisInfo.Registrar.DomainDNSSEC)

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

		content += fmt.Sprintf("\nadmin\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Admin.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Admin.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Admin.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Admin.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Admin.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Admin.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Admin.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Admin.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Admin.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Admin.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Admin.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Admin.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Admin.Email)

		content += fmt.Sprintf("\ntech\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Tech.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Tech.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Tech.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Tech.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Tech.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Tech.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Tech.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Tech.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Tech.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Tech.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Tech.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Tech.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Tech.Email)

		content += fmt.Sprintf("\nbill\n")
		content += fmt.Sprintf("id: %s\n", whoisInfo.Bill.ID)
		content += fmt.Sprintf("name: %s\n", whoisInfo.Bill.Name)
		content += fmt.Sprintf("organization: %s\n", whoisInfo.Bill.Organization)
		content += fmt.Sprintf("street: %s\n", whoisInfo.Bill.Street)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Bill.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Bill.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Bill.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Bill.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Bill.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Bill.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Bill.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Bill.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Bill.Email)

		err = xfile.WriteText("./examples/"+fileName+".out", content)
		assert.Nil(t, err)

		if !assert.IsContains(exts, fileExt) {
			exts = append(exts, fileExt)
		}

		if _, ok := domains[fileExt]; !ok {
			domains[fileExt] = []string{}
		}

		domains[fileExt] = append(domains[fileExt], strings.ToLower(whoisInfo.Registrar.DomainName))
	}

	sort.Strings(exts)
	verified := VERIFIEDLIST

	for _, k := range exts {
		sort.Strings(domains[k])
		for _, vv := range domains[k] {
			verified += fmt.Sprintf("| .%s | [%s](%s_%s) | [%s](%s_%s.out) | √ |\n",
				k, vv, k, vv, vv, k, vv)
		}
	}

	err = xfile.WriteText("./examples/README.md", strings.TrimSpace(verified))
	assert.Nil(t, err)
}
