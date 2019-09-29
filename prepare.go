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
	"fmt"
	"regexp"
	"strings"

	"github.com/likexian/gokit/assert"
)

var (
	textReplacer = regexp.MustCompile(`\n\[(.+?)\][\ ]+(.+?)`)
	chDomain     = regexp.MustCompile(`Domain name\s+[a-z0-9\-]+\.ch`)
	itDomain     = regexp.MustCompile(`Domain\:\s+[a-z0-9\-]+\.it`)
)

// Prepare do prepare the whois info for parsing
func Prepare(text string) string {
	text = strings.Replace(text, "\r", "", -1)
	text = strings.Replace(text, "\t", " ", -1)
	text = textReplacer.ReplaceAllString(text, "\n$1: $2")

	m := chDomain.FindStringSubmatch(text)
	if len(m) > 0 {
		return prepareCH(text)
	}

	m = itDomain.FindStringSubmatch(text)
	if len(m) > 0 {
		return prepareIT(text)
	}

	return text
}

// prepareCH do prepare the .ch domain
func prepareCH(text string) string {
	tokens := []string{
		"Domain name",
		"Holder",
		"Technical contact",
		"Registrar",
		"DNSSEC",
		"Name servers",
		"First registration date",
	}

	splits := map[string]string{
		"Holder":            "Registrant organization, Registrant name, Registrant street",
		"Technical contact": "Technical organization, Technical name, Technical street",
	}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		found := false
		for _, t := range tokens {
			if strings.HasPrefix(strings.ToLower(v)+" ", strings.ToLower(t+" ")) {
				found = true
				result += fmt.Sprintf("\n%s: %s", strings.TrimSpace(t), strings.TrimSpace(v[len(t):]))
				break
			}
		}
		if !found {
			result += ", " + v
		}
	}

	results := []string{}
	for _, v := range strings.Split(result, "\n") {
		if !strings.Contains(v, ":") {
			continue
		}
		vs := strings.Split(v, ":")
		if sp, ok := splits[vs[0]]; ok {
			vv := strings.Split(vs[1], ", ")
			ss := strings.Split(sp, ", ")
			if len(vv) > len(ss) {
				vv[len(ss)-1] = strings.Join(vv[len(ss)-1:], ", ")
				vv = vv[:len(ss)]
			}
			for k := range vv {
				results = append(results, fmt.Sprintf("%s: %s", ss[k], vv[k]))
			}
		} else {
			results = append(results, v)
		}
	}

	text = strings.Join(results, "\n")
	text = strings.Replace(text, ": ,", ":", -1)

	return text
}

// prepareIT do prepare the .it domain
func prepareIT(text string) string {
	topTokens := []string{
		"Registrant",
		"Admin Contact",
		"Technical Contacts",
		"Registrar",
		"Nameservers",
	}

	topToken := ""
	subToken := ""

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if assert.IsContains(topTokens, v) {
			topToken = v + " "
			subToken = ""
		} else {
			if v[0] != '*' && strings.Contains(v, ":") {
				vs := strings.Split(v, ":")
				subToken = vs[0]
			} else {
				if subToken != "" {
					result += ", " + v
					continue
				}
			}
			if topToken != "" && !strings.Contains(v, ":") {
				result += fmt.Sprintf("\n%s: %s", topToken, v)
			} else {
				result += fmt.Sprintf("\n%s%s", topToken, v)
			}
		}
	}

	return result
}
