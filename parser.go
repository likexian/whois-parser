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
	"fmt"
	"regexp"
	"strings"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xslice"
	"golang.org/x/net/idna"
)

// Version returns package version
func Version() string {
	return "1.24.20"
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
func Parse(text string) (whoisInfo WhoisInfo, err error) { //nolint:cyclop
	// Handle multi-stage WHOIS responses (IANA + registrar)
	cleanedText, wasMultiStage := handleMultiStageWhois(text)
	if wasMultiStage {
		fmt.Printf("DEBUG: Using cleaned text for parsing (length: %d -> %d)\n", len(text), len(cleanedText))
		text = cleanedText
	}

	name, extension := searchDomain(text)
	if name == "" {
		err = getDomainErrorType(text)
		return
	}

	if extension != "" && isExtNotFoundDomain(text, extension) {
		err = ErrNotFoundDomain
		return
	}

	domain := &Domain{}
	registrar := &Contact{}
	registrant := &Contact{}
	administrative := &Contact{}
	technical := &Contact{}
	billing := &Contact{}
	abuse := &Abuse{}

	domain.Name, _ = idna.ToASCII(name)
	domain.Extension, _ = idna.ToASCII(extension)

	whoisText, _ := Prepare(text, domain.Extension)
	whoisLines := strings.Split(whoisText, "\n")

	// Track current contact type for IANA-style format
	currentContactType := ""

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
			i++
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i--
		}

		lines := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		keyName := searchKeyName(name)

		// Debug output - remove this after fixing
		if strings.Contains(strings.ToLower(name), "contact") || strings.Contains(strings.ToLower(name), "name") || strings.Contains(strings.ToLower(name), "organisation") {
			fmt.Printf("DEBUG: name='%s', keyName='%s', value='%s', currentContactType='%s'\n", name, keyName, value, currentContactType)
		}

		// Handle IANA-style contact format - check the original name too
		if keyName == "contact" || strings.ToLower(name) == "contact" {
			currentContactType = strings.ToLower(value)
			fmt.Printf("DEBUG: Set currentContactType to '%s'\n", currentContactType)
			continue
		}

		switch keyName {
		case "domain_id":
			domain.ID = value
		case "domain_name":
			// Clean the value
			if firstSpace := strings.IndexByte(value, ' '); firstSpace > 0 {
				value = value[:firstSpace]
			}
			cleanValue := strings.ToLower(value)

			// Prioritize actual domain names over TLD registry entries
			// If we already have a domain, only overwrite if the new one looks like an actual domain (has dots)
			if domain.Domain == "" || (strings.Contains(cleanValue, ".") && !strings.Contains(domain.Domain, ".")) {
				domain.Domain = cleanValue
				domain.Punycode, _ = idna.ToASCII(domain.Domain)
				fmt.Printf("DEBUG: Set domain.Domain to '%s' (from value '%s')\n", domain.Domain, value)
			}
		case "domain_status":
			domain.Status = append(domain.Status, strings.Split(value, ",")...)
		case "domain_dnssec":
			if !domain.DNSSec {
				domain.DNSSec = isDNSSecEnabled(value)
			}
		case "whois_server":
			if domain.WhoisServer == "" {
				domain.WhoisServer = value
			}
		case "name_servers":
			domain.NameServers = append(domain.NameServers, strings.Split(value, ",")...)
		case "created_date":
			if domain.CreatedDate == "" {
				domain.CreatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.CreatedDateInTime = &parsed
				}
			}
		case "updated_date":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.UpdatedDateInTime = &parsed
				}
			}
		case "expired_date":
			if domain.ExpirationDate == "" {
				domain.ExpirationDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.ExpirationDateInTime = &parsed
				}
			}
		case "referral_url":
			registrar.ReferralURL = value
		case "registrar_id":
			registrar.ID = value
		case "registrar_name":
			registrar.Name = value
		case "registrar abuse contact email":
			abuse.Email = value
		case "registrar abuse contact phone":
			abuse.Phone = value
		default:
			// Handle contact information
			originalName := name
			name = clearKeyName(name)

			// Determine contact type and field name
			var contactType string
			var fieldName string

			// First check if we have a current contact type from IANA format
			if currentContactType != "" {
				contactType = currentContactType
				fieldName = mapIANAFieldName(originalName, currentContactType)
			} else {
				// Fall back to original logic for other formats
				if !strings.Contains(name, " ") {
					if name == "registrar" {
						name += " name"
					} else if domain.Extension == "dk" {
						name = "registrant " + name
					} else {
						name += " organization"
					}
				}
				ns := strings.SplitN(name, " ", 2)
				contactType = ns[0]
				fieldName = strings.TrimSpace("registrant " + ns[1])
			}

			// Route to appropriate contact struct
			if contactType == "registrar" || contactType == "registration" {
				parseContact(registrar, fieldName, value)
			} else if contactType == "registrant" || contactType == "holder" {
				parseContact(registrant, fieldName, value)
			} else if contactType == "admin" || contactType == "administrative" {
				parseContact(administrative, fieldName, value)
			} else if contactType == "tech" || contactType == "technical" {
				parseContact(technical, fieldName, value)
			} else if contactType == "bill" || contactType == "billing" {
				parseContact(billing, fieldName, value)
			}
		}
	}

	domain.NameServers = fixNameServers(domain.NameServers)
	domain.Status = fixDomainStatus(domain.Status)

	domain.NameServers = xslice.Unique(domain.NameServers).([]string)
	domain.Status = xslice.Unique(domain.Status).([]string)

	whoisInfo.Domain = domain
	if *registrar != (Contact{}) {
		whoisInfo.Registrar = registrar
	}

	if *registrant != (Contact{}) {
		whoisInfo.Registrant = registrant
	}

	if *administrative != (Contact{}) {
		whoisInfo.Administrative = administrative
	}

	if *technical != (Contact{}) {
		whoisInfo.Technical = technical
	}

	if *billing != (Contact{}) {
		whoisInfo.Billing = billing
	}

	if *abuse != (Abuse{}) {
		whoisInfo.Abuse = abuse
	}

	return
}

// mapIANAFieldName maps IANA field names to standard contact field names
func mapIANAFieldName(fieldName, contactType string) string {
	fieldName = strings.ToLower(fieldName)

	// Use the contact type to determine prefix (administrative, technical, etc.)
	prefix := "registrant"
	if contactType != "" {
		switch contactType {
		case "administrative":
			prefix = "registrant" // Map administrative to registrant for now
		case "technical":
			prefix = "registrant" // The parser expects registrant_ prefix for all contacts
		default:
			prefix = "registrant"
		}
	}

	switch fieldName {
	case "name":
		return prefix + "_name"
	case "organisation", "organization":
		return prefix + "_organization"
	case "address":
		return prefix + "_street"
	case "phone":
		return prefix + "_phone"
	case "fax-no", "fax":
		return prefix + "_fax"
	case "e-mail", "email":
		return prefix + "_email"
	default:
		// For unknown fields, try to map them generically
		return prefix + "_" + strings.Replace(fieldName, "-", "_", -1)
	}
}

// parseContact do parse contact info
func parseContact(contact *Contact, name, value string) {
	switch searchKeyName(name) {
	case "registrant_id":
		contact.ID = value
	case "registrant_name":
		if contact.Name == "" {
			contact.Name = value
		}
	case "registrant_organization":
		if contact.Organization == "" {
			contact.Organization = value
		}
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
}

var searchDomainRx1 = regexp.MustCompile(`(?i)\[?domain\:?(\s*\_?name)?\]?[\s\.]*\:?` +
	`\s*([^\s\,\;\@\(\)]+)\.([^\s\,\;\(\)\.]{2,})`)
var searchDomainRx2 = regexp.MustCompile(`(?i)\[?domain\:?(\s*\_?name)?\]?[\s\.]*\:?` +
	`\s*([^\s\,\;\@\(\)\.]{2,})\n`)

// Multi-stage WHOIS detection patterns
var ianaPatternRx = regexp.MustCompile(`(?i)%\s*IANA\s+WHOIS\s+server`)
var registrarSectionRx = regexp.MustCompile(`(?i)^\s*Domain\s+Name:\s*([^\s\r\n]+)\s*$`)
var sourceIanaRx = regexp.MustCompile(`(?i)source:\s*IANA\s*$`)

// handleMultiStageWhois detects and handles multi-stage WHOIS responses (IANA + registrar)
func handleMultiStageWhois(text string) (cleanedText string, wasMultiStage bool) {
	// Check if this is a multi-stage response (contains IANA section)
	if !ianaPatternRx.MatchString(text) {
		return text, false
	}

	lines := strings.Split(text, "\n")
	var registrarStart = -1
	var ianaEnd = -1

	// Find the end of IANA section (marked by "source: IANA")
	for i, line := range lines {
		if sourceIanaRx.MatchString(line) {
			ianaEnd = i
			break
		}
	}

	// Find the start of registrar section (marked by "Domain Name: specific.domain")
	for i := ianaEnd + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if registrarSectionRx.MatchString(line) {
			registrarStart = i
			break
		}
	}

	// If we found both sections, combine them strategically
	if ianaEnd > 0 && registrarStart > 0 {
		ianaLines := lines[0 : ianaEnd+1]
		registrarLines := lines[registrarStart:]

		// Extract IANA contacts while prioritizing registrar domain data
		ianaText := strings.Join(ianaLines, "\n")
		registrarText := strings.Join(registrarLines, "\n")

		// Combine: IANA contacts + registrar domain data
		cleanedText = ianaText + "\n\n" + registrarText

		fmt.Printf("DEBUG: Detected multi-stage WHOIS. IANA ends at line %d, registrar starts at line %d\n", ianaEnd+1, registrarStart+1)
		fmt.Printf("DEBUG: Combined IANA contacts with registrar data (total length: %d)\n", len(cleanedText))
		return cleanedText, true
	}

	// If we have IANA marker but couldn't separate properly,
	// try to find any "Domain Name:" line that's not just a TLD
	for i, line := range lines {
		if matches := registrarSectionRx.FindStringSubmatch(line); len(matches) > 1 {
			domain := strings.ToLower(strings.TrimSpace(matches[1]))
			// Check if this looks like an actual domain (contains a dot and isn't just a TLD)
			if strings.Contains(domain, ".") && len(strings.Split(domain, ".")) >= 2 {
				registrarLines := lines[i:]
				cleanedText = strings.Join(registrarLines, "\n")
				fmt.Printf("DEBUG: Found specific domain section starting at line %d for domain: %s\n", i+1, domain)
				return cleanedText, true
			}
		}
	}

	// If we still can't separate, return original text but mark as multi-stage
	fmt.Printf("DEBUG: Detected IANA response but couldn't separate sections cleanly\n")
	return text, true
}

// searchDomain finds domain name and extension from whois information
func searchDomain(text string) (name, extension string) {
	lines := strings.Split(text, "\n")

	// First priority: Look for "Domain Name: X.Y" AFTER any IANA section
	// This ensures we get registrar data, not registry data
	domainNameRx := regexp.MustCompile(`(?i)^\s*Domain\s+Name:\s*([^\s\r\n]+)\s*$`)

	var foundIANA = false
	for _, line := range lines {
		// Check if we've passed the IANA section
		if sourceIanaRx.MatchString(line) {
			foundIANA = true
			continue
		}

		if matches := domainNameRx.FindStringSubmatch(line); len(matches) > 1 {
			fullDomain := strings.ToLower(strings.TrimSpace(matches[1]))
			// If we found IANA section earlier, prioritize domains found after it
			if foundIANA && strings.Contains(fullDomain, ".") {
				parts := strings.Split(fullDomain, ".")
				if len(parts) >= 2 {
					extension = parts[len(parts)-1]
					nameParts := parts[:len(parts)-1]
					name = strings.Join(nameParts, ".")
					fmt.Printf("DEBUG: Found domain via Domain Name pattern (post-IANA): %s.%s\n", name, extension)
					return
				}
			}
			// If no IANA section found, use any valid domain
			if !foundIANA && strings.Contains(fullDomain, ".") {
				parts := strings.Split(fullDomain, ".")
				if len(parts) >= 2 {
					extension = parts[len(parts)-1]
					nameParts := parts[:len(parts)-1]
					name = strings.Join(nameParts, ".")
					fmt.Printf("DEBUG: Found domain via Domain Name pattern: %s.%s\n", name, extension)
					return
				}
			}
		}
	}

	// Second priority: Original regex patterns for backwards compatibility
	m := searchDomainRx1.FindStringSubmatch(text)
	if len(m) > 0 {
		candidateName := strings.TrimPrefix(strings.TrimSpace(m[2]), "\"")
		candidateExt := strings.TrimSuffix(strings.TrimSpace(m[3]), "\"")

		// Avoid matching IANA registry patterns like "domain: COM"
		if !(len(candidateName) <= 3 && candidateExt == "") {
			name = candidateName
			extension = candidateExt
			fmt.Printf("DEBUG: Found domain via regex1: %s.%s\n", name, extension)
		}
	}

	// Third priority: Single word domains (TLD only) - but avoid IANA patterns
	if name == "" {
		m := searchDomainRx2.FindStringSubmatch(text)
		if len(m) > 0 {
			candidateName := strings.TrimSpace(m[2])
			// Don't match single TLD words like "COM" from IANA registry
			if len(candidateName) > 3 {
				name = candidateName
				extension = ""
				fmt.Printf("DEBUG: Found domain via regex2 (TLD only): %s\n", name)
			}
		}
	}

	if name != "" {
		name = strings.ToLower(name)
		extension = strings.ToLower(extension)
	}

	return
}
