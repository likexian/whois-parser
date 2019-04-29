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
	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xfile"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	assert.Contains(t, Version(), ".")
	assert.Contains(t, Author(), "likexian")
	assert.Contains(t, License(), "Apache License")
}

func TestWhoisParser(t *testing.T) {
	_, err := Parse("not found")
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("%s", err), "Domain is not found.")

	_, err = Parse("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("%s", err), "Domain query limit exceeded.")

	_, err = Parse("Hello - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("%s", err), "Domain whois data invalid.")

	dirs, err := xfile.ListDir("./examples/", "file", -1)
	assert.Nil(t, err)

	for _, v := range dirs {
		domain := v.Name
		domainExt := domain[strings.LastIndex(domain, ".")+1:]
		whoisRaw, err := xfile.ReadText("./examples/" + domain)
		assert.Nil(t, err)

		if domain[len(domain)-4:] == ".out" {
			continue
		}

		whoisInfo, err := Parse(whoisRaw)
		assert.Nil(t, err)

		if domain == "mjj.com" {
			assert.NotZero(t, whoisInfo.Registrar.DomainId)
			assert.NotZero(t, whoisInfo.Registrar.RegistrarID)
		}

		if !assert.IsContains([]string{"museum", "at", "int", "jp"}, domainExt) {
			assert.NotZero(t, whoisInfo.Registrar.RegistrarName)
		}

		if domainExt == "com" {
			assert.NotZero(t, whoisInfo.Registrar.WhoisServer)
			assert.NotZero(t, whoisInfo.Registrar.ReferralURL)
		}

		assert.NotZero(t, whoisInfo.Registrar.DomainName)
		if !assert.IsContains([]string{"at", "kr", "int"}, domainExt) {
			assert.NotZero(t, whoisInfo.Registrar.DomainStatus)
		}

		if !assert.IsContains([]string{"au", "at", "int", "jp"}, domainExt) {
			assert.NotZero(t, whoisInfo.Registrar.CreatedDate)
		}

		if !assert.IsContains([]string{"cn", "ru", "su", "hk"}, domainExt) {
			assert.NotZero(t, whoisInfo.Registrar.UpdatedDate)
		}

		if !assert.IsContains([]string{"au", "at", "re", "fr", "int"}, domainExt) {
			assert.NotZero(t, whoisInfo.Registrar.ExpirationDate)
		}

		assert.NotZero(t, whoisInfo.Registrar.NameServers)
		if domainExt == "cn" {
			assert.NotZero(t, whoisInfo.Registrar.DomainDNSSEC)
		}

		content := ""
		content += fmt.Sprintf("registrar_id: %s\n", whoisInfo.Registrar.RegistrarID)
		content += fmt.Sprintf("registrar_name: %s\n", whoisInfo.Registrar.RegistrarName)
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
		content += fmt.Sprintf("street_ext: %s\n", whoisInfo.Registrant.StreetExt)
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
		content += fmt.Sprintf("street_ext: %s\n", whoisInfo.Admin.StreetExt)
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
		content += fmt.Sprintf("street_ext: %s\n", whoisInfo.Tech.StreetExt)
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
		content += fmt.Sprintf("street_ext: %s\n", whoisInfo.Bill.StreetExt)
		content += fmt.Sprintf("city: %s\n", whoisInfo.Bill.City)
		content += fmt.Sprintf("province: %s\n", whoisInfo.Bill.Province)
		content += fmt.Sprintf("postal_code: %s\n", whoisInfo.Bill.PostalCode)
		content += fmt.Sprintf("country: %s\n", whoisInfo.Bill.Country)
		content += fmt.Sprintf("phone: %s\n", whoisInfo.Bill.Phone)
		content += fmt.Sprintf("phone_ext: %s\n", whoisInfo.Bill.PhoneExt)
		content += fmt.Sprintf("fax: %s\n", whoisInfo.Bill.Fax)
		content += fmt.Sprintf("fax_ext: %s\n", whoisInfo.Bill.FaxExt)
		content += fmt.Sprintf("email: %s\n", whoisInfo.Bill.Email)

		xfile.WriteText("./examples/"+v.Name+".out", content)
	}
}
