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
	"sort"
	"strings"
	"time"
)

// isDNSSecEnabled returns if domain dnssec is enabled
func isDNSSecEnabled(data string) bool {
	switch strings.ToLower(data) {
	case "yes", "active", "signed", "signeddelegation", "signed delegation":
		return true
	default:
		return false
	}
}

// clearKeyName returns cleared key name
func clearKeyName(key string) string {
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

// searchKeyName returns the mapper value by key
func searchKeyName(key string) string {
	key = clearKeyName(key)
	if v, ok := keyRule[key]; ok {
		return v
	}

	return ""
}

// fixDomainStatus returns fixed domain status
func fixDomainStatus(status []string) []string {
	for k, v := range status {
		names := strings.Split(strings.TrimSpace(v), " ")
		status[k] = strings.ToLower(names[0])
		if status[k] == "not" && len(names) > 1 && strings.ToLower(names[1]) == "delegated" {
			status[k] = "not delegated"
		}
	}

	return status
}

// fixNameServers returns fixed name servers
func fixNameServers(servers []string) []string {
	for k, v := range servers {
		names := strings.Split(strings.TrimSpace(v), " ")
		servers[k] = strings.ToLower(strings.Trim(names[0], "."))
	}

	return servers
}

// containsIn returns if any of substrs contains in data
func containsIn(data string, substrs []string) bool {
	for _, v := range substrs {
		if strings.Contains(data, v) {
			return true
		}
	}

	return false
}

// Keys returns all keys of map by sort
func keys(m map[string]string) []string {
	r := []string{}

	for k := range m {
		r = append(r, k)
	}

	sort.Strings(r)

	return r
}

// parseDateString attempts to parse a given date using a collection of common
// format strings. Date formats containing time components are tried first
// before attempts are made using date-only formats.
func parseDateString(datetime string) (time.Time, error) {
	datetime = strings.Trim(datetime, ".")
	datetime = strings.ReplaceAll(datetime, ". ", "-")

	formats := [...]string{
		// Date & time formats
		"2006-01-02 15:04:05",
		"2006.01.02 15:04:05",
		"02/01/2006 15:04:05",
		"02.01.2006 15:04:05",
		"02.1.2006 15:04:05",
		"2.1.2006 15:04:05",
		"02-Jan-2006 15:04:05",
		"20060102 15:04:05",
		time.ANSIC,
		time.Stamp,
		time.StampMilli,
		time.StampMicro,
		time.StampNano,

		// Date, time & time zone formats
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05 (MST+3)",
		time.UnixDate,
		time.RubyDate,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC3339,
		time.RFC3339Nano,

		// Date only formats
		"2006-01-02",
		"02-Jan-2006",
		"02.01.2006",
		"02-01-2006",
		"January _2 2006",
		"Mon Jan _2 2006",
		"02/01/2006",
		"01/02/2006",
		"2006/01/02",
		"2006-Jan-02",
		"before Jan-2006",
	}

	for _, format := range formats {
		result, err := time.Parse(format, datetime)
		if err != nil {
			continue
		}
		return result, nil
	}

	return time.Now(), fmt.Errorf("could not parse %s as a date", datetime)
}
