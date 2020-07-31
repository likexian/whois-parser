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
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	"testing"

	"github.com/likexian/gokit/assert"
)

func TestIsBlockedDomain(t *testing.T) {
	// from `whois google.chat`
	_, err := Parse("The registration of this domain is restricted, as it is currently protected by a DPML Block. Additional information can be found at http://www.donuts.domains/what-we-do/brand-protection.")
	assert.Equal(t, err, ErrBlockedDomain)
}

func TestIsPremiumDomain(t *testing.T) {
	// from `good.games`
	_, err := Parse("This platinum domain is available for purchase. If you would like to make an offer, please contact platinums@donuts.email.")
	assert.Equal(t, err, ErrPremiumDomain)

	// from `cool.guru`
	_, err = Parse("This premium domain is available for purchase. If you would like to make an offer, please contact platinums@donuts.email.")
	assert.Equal(t, err, ErrPremiumDomain)

	// from `cool.fyi`
	_, err = Parse("This name is reserved by the Registry in accordance with ICANN Policy.")
	assert.Equal(t, err, ErrPremiumDomain)

	// from `good.download`
	_, err = Parse("Reserved Domain Name")
	assert.Equal(t, err, ErrPremiumDomain)
}
