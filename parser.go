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
	"errors"
	"regexp"
	"strings"

	"github.com/likexian/gokit/assert"
)

// Domain info error and replacer variables
var (
	ErrDomainNotFound    = errors.New("Domain is not found.")
	ErrDomainInvalidData = errors.New("Domain whois data invalid.")
	ErrDomainLimitExceed = errors.New("Domain query limit exceeded.")
)

// Version returns package version
func Version() string {
	return "1.10.1"
}

// Author returns package author
func Author() string {
	return "[Li Kexian](https://www.likexian.com/)"
}

// License returns package license
func License() string {
	return "Licensed under the Apache License 2.0"
}

// Parse returns parsed whois info
func Parse(text string) (whoisInfo WhoisInfo, err error) {
	name, extension := searchDomain(text)
	if name == "" {
		err = ErrDomainInvalidData
		if IsNotFound(text) {
			err = ErrDomainNotFound
		} else if IsLimitExceeded(text) {
			err = ErrDomainLimitExceed
		}
		return
	}

	var domain Domain
	var registrar Contact
	var registrant Contact
	var administrative Contact
	var technical Contact
	var billing Contact

	domain.Name = name
	domain.Extension = extension

	whoisText, _ := Prepare(text, extension)
	whoisLines := strings.Split(whoisText, "\n")
	for i := 0; i < len(whoisLines); i++ {
		line := strings.TrimSpace(whoisLines[i])
		if len(line) < 5 || !strings.Contains(line, ":") {
			continue
		}

		fChar := line[:1]
		if assert.IsContains([]string{"-", "*", "%", ">", ";"}, fChar) {
			continue
		}

		if line[len(line)-1:] == ":" {
			i += 1
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i -= 1
		}

		lines := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		keyName := FindKeyName(name)
		switch keyName {
		case "domain_id":
			domain.ID = value
		case "domain_name":
			domain.Domain = value
		case "domain_status":
			domain.Status += value + ","
		case "domain_dnssec":
			if domain.DNSSEC == "" {
				domain.DNSSEC = value
			}
		case "whois_server":
			if domain.WhoisServer == "" {
				domain.WhoisServer = value
			}
		case "name_servers":
			domain.NameServers += value + ","
		case "created_date":
			if domain.CreatedDate == "" {
				domain.CreatedDate = value
			}
		case "updated_date":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = value
			}
		case "expired_date":
			if domain.ExpirationDate == "" {
				domain.ExpirationDate = value
			}
		case "referral_url":
			registrar.ReferralURL = value
		default:
			name = ClearName(name)
			if !strings.Contains(name, " ") {
				name += " name"
			}
			ns := strings.SplitN(name, " ", 2)
			name = strings.TrimSpace("registrant " + ns[1])
			if ns[0] == "registrar" || ns[0] == "registration" {
				registrar = parseContact(registrar, name, value)
			} else if ns[0] == "registrant" || ns[0] == "holder" {
				registrant = parseContact(registrant, name, value)
			} else if ns[0] == "admin" || ns[0] == "administrative" {
				administrative = parseContact(administrative, name, value)
			} else if ns[0] == "tech" || ns[0] == "technical" {
				technical = parseContact(technical, name, value)
			} else if ns[0] == "bill" || ns[0] == "billing" {
				billing = parseContact(billing, name, value)
			}
		}
	}

	domain.NameServers = FixNameServers(strings.ToLower(domain.NameServers))
	domain.Status = FixDomainStatus(strings.ToLower(domain.Status))

	domain.NameServers = RemoveDuplicateField(domain.NameServers)
	domain.Status = RemoveDuplicateField(domain.Status)

	whoisInfo.Domain = domain
	whoisInfo.Registrar = registrar
	whoisInfo.Registrant = registrant
	whoisInfo.Administrative = administrative
	whoisInfo.Technical = technical
	whoisInfo.Billing = billing

	return
}

// parseContact do parse contact info
func parseContact(contact Contact, name, value string) Contact {
	keyName := FindKeyName(name)

	switch keyName {
	case "registrant_id":
		contact.ID = value
	case "registrant_name":
		contact.Name = value
	case "registrant_organization":
		contact.Organization = value
	case "registrant_street":
		if contact.Street == "" {
			contact.Street = value
		} else {
			contact.Street += ", " + value
		}
	case "registrant_city":
		contact.City = value
	case "registrant_state_province":
		contact.Province = value
	case "registrant_postal_code":
		contact.PostalCode = value
	case "registrant_country":
		contact.Country = value
	case "registrant_phone":
		contact.Phone = value
	case "registrant_phone_ext":
		contact.PhoneExt = value
	case "registrant_fax":
		contact.Fax = value
	case "registrant_fax_ext":
		contact.FaxExt = value
	case "registrant_email":
		contact.Email = strings.ToLower(value)
	}

	return contact
}

// searchDomain find domain from whois info
func searchDomain(text string) (string, string) {
	r := regexp.MustCompile(`(?i)\[?domain(\s*\_?name)?\]?\s*\:?\s*([a-z0-9\-\.]+)\.([a-z]{2,})`)
	m := r.FindStringSubmatch(text)
	if len(m) > 0 {
		return strings.ToLower(strings.TrimSpace(m[2])), strings.ToLower(strings.TrimSpace(m[3]))
	}

	r = regexp.MustCompile(`(?i)\[?domain(\s*\_?name)?\]?\s*\:?\s*([a-z]{2,})\n`)
	m = r.FindStringSubmatch(text)
	if len(m) > 0 {
		return strings.ToLower(strings.TrimSpace(m[2])), ""
	}

	return "", ""
}
