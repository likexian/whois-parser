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
	"testing"

	"github.com/likexian/gokit/assert"
)

func TestIsDomainNotFound(t *testing.T) {
	// iamnotexistsdomain.CN
	data := `No matching record.`
	assert.True(t, IsDomainNotFound(data))

	// iamnotexistsdomain.com
	data = `No match for "IAMNOTEXISTSDOMAIN.COM".
	>>> Last update of whois database: 2021-01-15T11:26:46Z <<<`
	assert.True(t, IsDomainNotFound(data))

	// iam.com
	data = `Domain Name: IAM.COM
	Registry Domain ID: 2017209_DOMAIN_COM-VRSN`
	assert.False(t, IsDomainNotFound(data))
}

func TestIsReservedDomain(t *testing.T) {
	// gov.cn
	data := `the Domain Name you apply can not be registered online. Please consult your Domain Name registrar`
	assert.True(t, IsReservedDomain(data))

	// good.download
	data = `Reserved Domain Name
	URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/`
	assert.True(t, IsReservedDomain(data))

	// iam.com
	data = `Domain Name: IAM.COM
	Registry Domain ID: 2017209_DOMAIN_COM-VRSN`
	assert.False(t, IsReservedDomain(data))
}

func TestIsPremiumDomain(t *testing.T) {
	// good.games
	data := `This platinum domain is available for purchase.
	If you would like to make an offer, please contact platinums@donuts.email.
	This name is reserved by the Registry in accordance with ICANN Policy.`
	assert.True(t, IsPremiumDomain(data))

	// cool.guru
	data = `Domain not found.
	This premium domain is available for purchase.
	If you would like to make an offer, please contact platinums@donuts.email.`
	assert.True(t, IsPremiumDomain(data))

	// iam.com
	data = `Domain Name: IAM.COM
	Registry Domain ID: 2017209_DOMAIN_COM-VRSN`
	assert.False(t, IsPremiumDomain(data))
}

func TestIsBlockedDomain(t *testing.T) {
	// google.chat
	data := `The registration of this domain is restricted,
	as it is protected by the Donuts DPML Brand Protection policy.
	Additional information can be found at https://donuts.domains/what-we-do/brand-protection.`
	assert.True(t, IsBlockedDomain(data))

	// google.lol
	data = `This name is not available for registration:
	This name subscribes to the Uni EPS+ product`
	assert.True(t, IsBlockedDomain(data))

	// paypal.sex
	data = `This name is not available for registration:
	This name subscribes to the AdultBlock product`
	assert.True(t, IsBlockedDomain(data))

	// iam.com
	data = `Domain Name: IAM.COM
	Registry Domain ID: 2017209_DOMAIN_COM-VRSN`
	assert.False(t, IsBlockedDomain(data))
}
