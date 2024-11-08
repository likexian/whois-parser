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
	"testing"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xfile"
)

func TestAsisNotFoundDomain(t *testing.T) {
	// iamnotexistsdomain.CN
	data := `No matching record.`
	assert.True(t, isNotFoundDomain(data))

	// iamnotexistsdomain.com
	data = `No match for "IAMNOTEXISTSDOMAIN.COM".
	>>> Last update of whois database: 2021-01-15T11:26:46Z <<<`
	assert.True(t, isNotFoundDomain(data))

	// likexian.com
	data = `Domain Name: LIKEXIAN.COM
	Registry Domain ID: 1665843940_DOMAIN_COM-VRSN`
	assert.False(t, isNotFoundDomain(data))
}

func TestAsisExtNotFoundDomain(t *testing.T) {
	dirs, err := xfile.ListDir(notfoundDir, xfile.TypeFile, -1)
	assert.Nil(t, err)

	for _, v := range dirs {
		if v.Name == "README.md" {
			continue
		}

		whoisRaw, err := xfile.ReadText(notfoundDir + "/" + v.Name)
		assert.Nil(t, err)

		_, extension := searchDomain(whoisRaw)
		if extension == "" {
			assert.True(t, isNotFoundDomain(whoisRaw), v.Name)
		} else {
			assert.True(t, isExtNotFoundDomain(whoisRaw, extension), v.Name)
		}
	}
}

func TestAsisReservedDomain(t *testing.T) {
	// gov.cn
	data := `the Domain Name you apply can not be registered online. Please consult your Domain Name registrar`
	assert.True(t, isReservedDomain(data))

	// good.download
	data = `Reserved Domain Name
	URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/`
	assert.True(t, isReservedDomain(data))

	// likexian.com
	data = `Domain Name: LIKEXIAN.COM
	Registry Domain ID: 1665843940_DOMAIN_COM-VRSN`
	assert.False(t, isReservedDomain(data))
}

func TestAsisPremiumDomain(t *testing.T) {
	// good.games
	data := `This platinum domain is available for purchase.
	If you would like to make an offer, please contact platinums@donuts.email.
	This name is reserved by the Registry in accordance with ICANN Policy.`
	assert.True(t, isPremiumDomain(data))

	// cool.guru
	data = `Domain not found.
	This premium domain is available for purchase.
	If you would like to make an offer, please contact platinums@donuts.email.`
	assert.True(t, isPremiumDomain(data))

	// likexian.com
	data = `Domain Name: LIKEXIAN.COM
	Registry Domain ID: 1665843940_DOMAIN_COM-VRSN`
	assert.False(t, isPremiumDomain(data))
}

func TestAsisBlockedDomain(t *testing.T) {
	// google.chat
	data := `The registration of this domain is restricted,
	as it is protected by the Donuts DPML Brand Protection policy.
	Additional information can be found at https://donuts.domains/what-we-do/brand-protection.`
	assert.True(t, isBlockedDomain(data))

	// google.lol
	data = `This name is not available for registration:
	This name subscribes to the Uni EPS+ product`
	assert.True(t, isBlockedDomain(data))

	// paypal.sex
	data = `This name is not available for registration:
	This name subscribes to the AdultBlock product`
	assert.True(t, isBlockedDomain(data))

	// likexian.com
	data = `Domain Name: LIKEXIAN.COM
	Registry Domain ID: 1665843940_DOMAIN_COM-VRSN`
	assert.False(t, isBlockedDomain(data))
}

func TestAsisLimitExceeded(t *testing.T) {
	// xxx.org
	data := `WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS`
	assert.True(t, isLimitExceeded(data))

	// whois.domain-registry.nl
	data = `whois.domain-registry.nl: Server too busy, try again later`
	assert.True(t, isLimitExceeded(data))

	// likexian.com
	data = `Domain Name: LIKEXIAN.COM
	Registry Domain ID: 1665843940_DOMAIN_COM-VRSN`
	assert.False(t, isLimitExceeded(data))

	data = `%% Maximum query rate reached`
	assert.True(t, isLimitExceeded(data))

	// GoDaddy (when blocking all queries)
	data = "Number of allowed queries exceeded\r\n"
	assert.True(t, isLimitExceeded(data))
}
