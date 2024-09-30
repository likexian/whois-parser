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
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrNotFoundDomain domain is not found
	ErrNotFoundDomain = errors.New("whoisparser: domain is not found")
	// ErrReservedDomain domain is reserved
	ErrReservedDomain = errors.New("whoisparser: domain is reserved to register")
	// ErrPremiumDomain domain is available to register at premium price
	ErrPremiumDomain = errors.New("whoisparser: domain is available at premium price")
	// ErrBlockedDomain domain is blocked due to brand protection
	ErrBlockedDomain = errors.New("whoisparser: domain is blocked due to brand protection")
	// ErrDomainDataInvalid domain whois data is invalid
	ErrDomainDataInvalid = errors.New("whoisparser: domain whois data is invalid")
	// ErrDomainLimitExceed domain whois query is limited
	ErrDomainLimitExceed = errors.New("whoisparser: domain whois query limit exceeded")
	// ErrNotFoundIP IP address is not found
	ErrNotFoundIP = errors.New("whoisparser: IP address is not found")
	// ErrIPDataInvalid IP whois data is invalid
	ErrIPDataInvalid = errors.New("whoisparser: IP whois data is invalid")
	// ErrIPLimitExceed IP whois query is limited
	ErrIPLimitExceed = errors.New("whoisparser: IP whois query limit exceeded")
)

// getErrorType returns error type of whois data
func getErrorType(data string) error {
	if isIPWhois(data) {
		return getIPErrorType(data)
	}
	return getDomainErrorType(data)
}

// getDomainErrorType returns error type of domain data
func getDomainErrorType(data string) error {
	switch {
	case isNotFoundDomain(data):
		return ErrNotFoundDomain
	case isBlockedDomain(data):
		return ErrBlockedDomain
	case isPremiumDomain(data):
		return ErrPremiumDomain
	case isReservedDomain(data):
		return ErrReservedDomain
	case isLimitExceeded(data):
		return ErrDomainLimitExceed
	default:
		return ErrDomainDataInvalid
	}
}

// getIPErrorType returns error type of IP data
func getIPErrorType(data string) error {
	switch {
	case isNotFoundIP(data):
		return ErrNotFoundIP
	case isLimitExceeded(data):
		return ErrIPLimitExceed
	default:
		return ErrIPDataInvalid
	}
}

// isNotFoundDomain returns if domain is not found
func isNotFoundDomain(data string) bool {
	notFoundKeys := []string{
		"is free",
		"no found",
		"no match",
		"not found",
		"not match",
		"not available",
		"no data found",
		"nothing found",
		"no entries found",
		"no matching record",
		"not registered",
		"not been registered",
		"object does not exist",
		"query returned 0 objects",
		"domain name not known",
	}

	return containsIn(strings.ToLower(data), notFoundKeys)
}

// isNotFoundIP returns if IP address is not found
func isNotFoundIP(data string) bool {
	notFoundKeys := []string{
		"no match found",
		"not found",
		"no data found",
		"no entries found",
	}

	return containsIn(strings.ToLower(data), notFoundKeys)
}

var reBlank = regexp.MustCompile(`\s+`)

// isExtNotFoundDomain returns if domain is not found by extension
func isExtNotFoundDomain(data, extension string) bool {
	data = reBlank.ReplaceAllString(data, " ")

	switch extension {
	case "ai", "cx", "gs":
		if strings.Contains(data, "Domain Status: No Object Found") {
			return true
		}
	case "de":
		if strings.Contains(data, "Status: free") {
			return true
		}
	case "eu", "it":
		if strings.Contains(data, "Status: AVAILABLE") {
			return true
		}
	case "nz":
		if strings.Contains(data, "query_status: 220 Available") {
			return true
		}
	case "pl":
		if strings.Contains(data, "No information available about domain name") {
			return true
		}
	case "sexy":
		if strings.Contains(data, "is available") {
			return true
		}
	case "love":
		if strings.Contains(data, "is available") {
			return true
		}
	case "nu":
		fallthrough
	case "se":
		if strings.Contains(data, "not found") {
			return true
		}
	}

	return false
}

// isReservedDomain returns if domain is reserved
func isReservedDomain(data string) bool {
	reservedKeys := []string{
		"reserved domain name",
		"reserved by the registry",
		"can not be registered online",
	}

	return containsIn(strings.ToLower(data), reservedKeys)
}

// isPremiumDomain returns if domain is available to register at premium price
func isPremiumDomain(data string) bool {
	premiumKeys := []string{
		"premium domain is available for purchase",
		"platinum domain is available for purchase",
	}

	return containsIn(strings.ToLower(data), premiumKeys)
}

// isBlockedDomain returns if domain is blocked due to brand protection
func isBlockedDomain(data string) bool {
	blockedKeys := []string{
		// Donuts DPML
		"dpml brand protection",
		// Uniregistry Uni EPS
		"subscribes to the uni eps",
		// Gandi AdultBlock
		"subscribes to the adultblock",
	}

	return containsIn(strings.ToLower(data), blockedKeys)
}

// isLimitExceeded returns if whois query is limited
func isLimitExceeded(data string) bool {
	limitExceedKeys := []string{
		"limit exceeded",
		"server too busy",
		"quota exceeded",
		"exceeded the maximum allowable",
		"exceeded your query limit",
		"restricted due to excessive queries",
		"due to query limit controls",
		"you have exceeded your allotted number of",
		"maximum daily connection limit reached",
		"maximum query rate reached",
	}

	return containsIn(strings.ToLower(data), limitExceedKeys)
}
