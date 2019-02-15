/*
 * Go module for whois info parser
 * https://www.likexian.com/
 *
 * Copyright 2014-2019, Li Kexian
 * Released under the Apache License, Version 2.0
 *
 */

package whoisparser

import (
	"io/ioutil"
	"strings"
)

// ReadFile read a text file and returns text string
func ReadFile(file string) (result string, err error) {
	tmpResult, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	result = string(tmpResult)
	return
}

// WriteFile write string to file
func WriteFile(file string, data string) (err error) {
	err = ioutil.WriteFile(file, []byte(data), 0644)
	return
}

// IsNotFound returns domain is not found
func IsNotFound(data string) (result bool) {
	data = strings.ToLower(data)
	return strings.Contains(data, "no found") || strings.Contains(data, "no match") ||
		strings.Contains(data, "not found") || strings.Contains(data, "not match") ||
		strings.Contains(data, "no entries found") || strings.Contains(data, "no data found") ||
		strings.Contains(data, "not registered") || strings.Contains(data, "is free") ||
		strings.Contains(data, "not available for registration")
}

// IsLimitExceeded returns is query limit
func IsLimitExceeded(data string) (result bool) {
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

	key = strings.TrimSpace(key)
	key = strings.ToLower(key)

	return key
}

// FindKeyName returns the mapper value by key
func FindKeyName(key string) (name string) {
	key = ClearName(key)
	if v, ok := keyRule[key]; ok {
		return v
	}

	return ""
}

// RemoveDuplicateField remove the duplicate field
func RemoveDuplicateField(data string) string {
	var newFields []string
	for _, v := range strings.Split(data, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !StringInArray(newFields, v) {
			newFields = append(newFields, v)
		}
	}

	return strings.Join(newFields, ",")
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

// StringInArray returrns string is in array
func StringInArray(array []string, find string) bool {
	for _, v := range array {
		if v == find {
			return true
		}
	}

	return false
}
