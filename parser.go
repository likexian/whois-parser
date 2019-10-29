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
	return "1.8.0"
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
	name, ext := searchDomain(text)
	if name == "" {
		err = ErrDomainInvalidData
		if IsNotFound(text) {
			err = ErrDomainNotFound
		} else if IsLimitExceeded(text) {
			err = ErrDomainLimitExceed
		}
		return
	}

	var registrar Registrar
	var registrant Registrant
	var admin Registrant
	var tech Registrant
	var bill Registrant

	whoisText, _ := Prepare(text, ext)
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
			registrar.DomainId = value
		case "domain_name":
			registrar.DomainName = value
		case "registrar_id":
			if registrar.ID == "" {
				registrar.ID = value
			}
		case "registrar_name":
			if registrar.Name == "" {
				registrar.Name = value
			}
		case "registrar_organization":
			if registrar.Organization == "" {
				registrar.Organization = value
			}
		case "registrar_phone":
			if registrar.Phone == "" {
				registrar.Phone = value
			}
		case "registrar_email":
			if registrar.Email == "" {
				registrar.Email = value
			}
		case "registrar_reseller":
			if registrar.Reseller == "" {
				registrar.Reseller = value
			}
		case "whois_server":
			if registrar.WhoisServer == "" {
				registrar.WhoisServer = value
			}
		case "referral_url":
			if registrar.ReferralURL == "" {
				registrar.ReferralURL = value
			}
		case "domain_status":
			registrar.DomainStatus += value + ","
		case "name_servers":
			registrar.NameServers += value + ","
		case "domain_dnssec":
			if registrar.DomainDNSSEC == "" {
				registrar.DomainDNSSEC = value
			}
		case "created_date":
			if registrar.CreatedDate == "" {
				registrar.CreatedDate = value
			}
		case "updated_date":
			if registrar.UpdatedDate == "" {
				registrar.UpdatedDate = value
			}
		case "expired_date":
			if registrar.ExpirationDate == "" {
				registrar.ExpirationDate = value
			}
		case "registrant_id":
			registrant.ID = value
		case "admin_id":
			admin.ID = value
		case "tech_id":
			tech.ID = value
		case "bill_id":
			bill.ID = value
		default:
			name = ClearName(name)
			if !strings.Contains(name, " ") {
				name += " name"
			}
			ns := strings.SplitN(name, " ", 2)
			name = strings.TrimSpace("registrant " + ns[1])
			if ns[0] == "registrant" || ns[0] == "holder" {
				registrant = parseRegistrant(registrant, name, value)
			} else if ns[0] == "admin" || ns[0] == "administrative" {
				admin = parseRegistrant(admin, name, value)
			} else if ns[0] == "tech" || ns[0] == "technical" {
				tech = parseRegistrant(tech, name, value)
			} else if ns[0] == "bill" || ns[0] == "billing" {
				bill = parseRegistrant(bill, name, value)
			}
		}
	}

	registrar.NameServers = FixNameServers(strings.ToLower(registrar.NameServers))
	registrar.DomainStatus = FixDomainStatus(strings.ToLower(registrar.DomainStatus))

	registrar.NameServers = RemoveDuplicateField(registrar.NameServers)
	registrar.DomainStatus = RemoveDuplicateField(registrar.DomainStatus)

	whoisInfo.Registrar = registrar
	whoisInfo.Registrant = registrant
	whoisInfo.Admin = admin
	whoisInfo.Tech = tech
	whoisInfo.Bill = bill

	return
}

// parseRegistrant do parse registrant info
func parseRegistrant(registrant Registrant, name, value string) Registrant {
	keyName := FindKeyName(name)
	switch keyName {
	case "registrant_id":
		registrant.ID = value
	case "registrant_name":
		registrant.Name = value
	case "registrant_organization":
		registrant.Organization = value
	case "registrant_street":
		if registrant.Street == "" {
			registrant.Street = value
		} else {
			registrant.Street += ", " + value
		}
	case "registrant_city":
		registrant.City = value
	case "registrant_state_province":
		registrant.Province = value
	case "registrant_postal_code":
		registrant.PostalCode = value
	case "registrant_country":
		registrant.Country = value
	case "registrant_phone":
		registrant.Phone = value
	case "registrant_phone_ext":
		registrant.PhoneExt = value
	case "registrant_fax":
		registrant.Fax = value
	case "registrant_fax_ext":
		registrant.FaxExt = value
	case "registrant_email":
		registrant.Email = strings.ToLower(value)
	}

	return registrant
}

// searchDomain find domain from whois info
func searchDomain(text string) (name, ext string) {
	name, ext = "", ""

	r := regexp.MustCompile(`(?i)\[?domain(\s*\_?name)?\]?\s*\:?\s*([a-z0-9\-\.]+)\.([a-z]{2,})`)
	m := r.FindStringSubmatch(text)
	if len(m) > 0 {
		name = strings.ToLower(strings.TrimSpace(m[2]))
		ext = strings.ToLower(strings.TrimSpace(m[3]))
	}

	return
}
