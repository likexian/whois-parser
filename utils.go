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
	"sort"
	"strings"

	"github.com/likexian/gokit/xslice"
)

// IsNotFound returns domain is not found
func IsNotFound(data string) bool {
	notExistsKeys := []string{
		"no found",
		"no match",
		"not found",
		"not match",
		"no entries found",
		"no data found",
		"not registered",
		"not been registered",
		"is free",
		"not available for registration",
		"object does not exist",
	}

	data = strings.ToLower(data)
	for _, v := range notExistsKeys {
		if strings.Contains(data, v) {
			return true
		}
	}

	return false
}

// IsLimitExceeded returns is query limit
func IsLimitExceeded(data string) bool {
	data = strings.ToLower(data)
	return strings.Contains(data, "limit exceeded")
}

// ClearName returns cleared key name
func ClearName(key string) string {
	if strings.Contains(key, "(") {
		key = strings.Split(key, "(")[0]
	}

	key = strings.Replace(key, "-", " ", -1)
	key = strings.Replace(key, "_", " ", -1)
	key = strings.Replace(key, "/", " ", -1)
	key = strings.Replace(key, "\\", " ", -1)
	key = strings.Replace(key, "'", " ", -1)
	key = strings.Replace(key, ".", " ", -1)

	key = strings.TrimPrefix(key, "Registry ")
	key = strings.TrimPrefix(key, "Sponsoring ")

	key = strings.TrimSpace(key)
	key = strings.ToLower(key)

	return key
}

// FindKeyName returns the mapper value by key
func FindKeyName(key string) string {
	key = ClearName(key)
	if v, ok := keyRule[key]; ok {
		return v
	}

	return ""
}

// RemoveDuplicateField remove the duplicate field
func RemoveDuplicateField(data string) string {
	fs := []string{}

	for _, v := range strings.Split(data, ",") {
		if strings.TrimSpace(v) != "" {
			fs = append(fs, v)
		}
	}

	fields := xslice.Unique(fs)
	result := strings.Join(fields.([]string), ",")

	return result
}

// FixDomainStatus returns fixed domain status
func FixDomainStatus(state string) string {
	states := strings.Split(state, ",")
	for k, v := range states {
		names := strings.Split(strings.TrimSpace(v), " ")
		states[k] = names[0]
	}

	return strings.Join(states, ",")
}

// FixNameServers returns fixed name servers
func FixNameServers(nservers string) string {
	servers := strings.Split(nservers, ",")
	for k, v := range servers {
		names := strings.Split(strings.TrimSpace(v), " ")
		servers[k] = strings.Trim(names[0], ".")
	}

	return strings.Join(servers, ",")
}

// Keys returns all keys of map by sort
func Keys(m map[string]string) []string {
	r := []string{}

	for k := range m {
		r = append(r, k)
	}

	sort.Strings(r)

	return r
}
