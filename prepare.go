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
	dotJPReplacer = regexp.MustCompile(`\n\[(.+?)\][\ ]*(.+?)?`)
	searchDomain  = regexp.MustCompile(`(?i)\[?Domain(\s+name)?\]?\:?\s+([a-z0-9\-]+)\.([a-z]{2,})`)
)

// Prepare do prepare the whois info for parsing
func Prepare(text string) string {
	text = strings.Replace(text, "\r", "", -1)
	text = strings.Replace(text, "\t", " ", -1)

	m := searchDomain.FindStringSubmatch(text)
	if len(m) > 0 {
		switch strings.ToLower(m[3]) {
		case "edu":
			return prepareEDU(text)
		case "ch":
			return prepareCH(text)
		case "it":
			return prepareIT(text)
		case "fr", "re", "tf", "yt", "pm", "wf":
			return prepareFR(text)
		case "ru":
			return prepareRU(text)
		case "jp":
			return prepareJP(text)
		}
	}

	return text
}

// prepareEDU do prepare the .edu domain
func prepareEDU(text string) string {
	tokens := map[string][]string{
		"Registrant:": {
			"Organization",
			"Address",
			"Address1",
			"Country",
		},
		"Administrative Contact:": {
			"Name",
			"Organization",
			"Address",
			"Address1",
			"Country",
			"Phone",
			"Email",
		},
		"Technical Contact:": {
			"Name",
			"Organization",
			"Address",
			"Address1",
			"Country",
			"Phone",
			"Email",
		},
	}

	token := ""
	index := 0

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.HasSuffix(v, ":") {
			token = ""
			index = 0
		}
		if _, ok := tokens[v]; ok {
			token = v
		} else {
			if token == "" {
				result += "\n" + v
			} else {
				result += fmt.Sprintf("\n%s %s: %s", token[:len(token)-1], tokens[token][index], v)
				index += 1
			}
		}
	}

	return result
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

// prepareFR do prepare the .fr domain
func prepareFR(text string) string {
	dsToken := "dsl-id"
	hdlToken := "nic-hdl"
	regToken := "registrar"

	tokens := map[string]string{
		"holder-c": "holder",
		"admin-c":  "admin",
		"tech-c":   "tech",
	}

	token := ""
	newBlock := false
	hdls := map[string]string{}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			newBlock = true
			continue
		}

		vs := strings.Split(v, ":")
		if newBlock && strings.TrimSpace(vs[0]) == regToken {
			token = regToken + " "
			v = fmt.Sprintf("name: %s", strings.TrimSpace(vs[1]))
		}

		newBlock = false
		if t, ok := tokens[strings.TrimSpace(vs[0])]; ok {
			hdls[t] = strings.TrimSpace(vs[1])
		}

		if strings.TrimSpace(vs[0]) == dsToken && strings.TrimSpace(vs[1]) != "" {
			v += "\nDNSSEC: signed"
		}

		if strings.TrimSpace(vs[0]) == hdlToken {
			for _, kk := range Keys(hdls) {
				if strings.TrimSpace(vs[1]) == hdls[kk] {
					token = kk + " "
					delete(hdls, kk)
					break
				}
			}
		}

		result += fmt.Sprintf("\n%s%s", token, v)
	}

	return result
}

// prepareRU do prepare the .ru domain
func prepareRU(text string) string {
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.Contains(v, ":") {
			continue
		}
		vs := strings.Split(v, ":")
		if strings.TrimSpace(vs[0]) == "person" {
			v = fmt.Sprintf("Registrant Name: %s", vs[1])
		}
		if strings.TrimSpace(vs[0]) == "org" {
			v = fmt.Sprintf("Registrant Organization: %s", vs[1])
		}
		result += v + "\n"
	}

	return result
}

// prepareJP do prepare the .jp domain
func prepareJP(text string) string {
	text = dotJPReplacer.ReplaceAllString(text, "\n$1: $2")

	adminToken := "Contact Information"
	addressToken := "Postal Address"

	token := ""
	prefixToken := ""

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.Split(v, ":")
			token = strings.TrimSpace(vs[0])
			if token == adminToken {
				prefixToken = "admin "
			}
		} else {
			if token == addressToken {
				result += ", " + v
				continue
			}
		}
		result += "\n" + prefixToken + v
	}

	return result
}
