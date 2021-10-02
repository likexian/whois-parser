/*
 * Copyright 2014-2021 Li Kexian
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
)

// Prepare do prepare the whois info for parsing
func Prepare(text, ext string) (string, bool) { //nolint:cyclop
	text = strings.Replace(text, "\r", "", -1)
	text = strings.Replace(text, "\t", " ", -1)
	text = strings.TrimSpace(text)

	switch ext {
	case "":
		return prepareTLD(text), true
	case "edu":
		return prepareEDU(text), true
	case "int":
		return prepareINT(text), true
	case "mo":
		return prepareMO(text), true
	case "hk":
		return prepareHK(text), true
	case "tw":
		return prepareTW(text), true
	case "ch":
		return prepareCH(text), true
	case "it":
		return prepareIT(text), true
	case "fr", "re", "tf", "yt", "pm", "wf":
		return prepareFR(text), true
	case "ru", "su", "xn--p1ai":
		return prepareRU(text), true
	case "fi":
		return prepareFI(text), true
	case "jp":
		return prepareJP(text), true
	case "uk":
		return prepareUK(text), true
	case "kr":
		return prepareKR(text), true
	case "nz":
		return prepareNZ(text), true
	case "tk":
		return prepareTK(text), true
	case "nl":
		return prepareNL(text), true
	case "eu":
		return prepareEU(text), true
	case "br":
		return prepareBR(text), true
	case "ir", "xn--mgba3a4f16a":
		return prepareIR(text), true
	case "rs":
		return prepareRS(text), true
	case "kz":
		return prepareKZ(text), true
	case "ee":
		return prepareEE(text), true
	case "cn", "xn--fiqs8s", "xn--fiqz9s":
		return prepareCN(text), true
	default:
		return text, false
	}
}

// prepareTLD do prepare the tld domain
func prepareTLD(text string) string {
	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.Split(v, ":")
			if strings.TrimSpace(vs[0]) == "organisation" {
				if token == "" {
					token = "registrant"
				}
			}
			if strings.TrimSpace(vs[0]) == "contact" {
				token = strings.TrimSpace(vs[1])
			} else {
				if token != "" {
					v = fmt.Sprintf("%s %s", token, v)
				}
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareEDU do prepare the .edu domain
func prepareEDU(text string) string {
	tokens := map[string][]string{
		"Registrant:": {
			"Organization",
			"Address",
			"Phone",
			"Email",
		},
		"Administrative Contact:": {
			"Name",
			"Organization",
			"Address",
			"Phone",
			"Email",
		},
		"Technical Contact:": {
			"Name",
			"Organization",
			"Address",
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
				// address ending now jump to phone
				if tokens[token][index] == "Address" && strings.HasPrefix(v, "+") {
					found := xslice.Index(tokens[token], "Phone")
					if found != -1 {
						index = found
					}
				}
				result += fmt.Sprintf("\n%s %s: %s", token[:len(token)-1], tokens[token][index], v)
				if tokens[token][index] != "Address" {
					index++
				}
			}
		}
	}

	return result
}

// prepareINT do prepare the .int domain
func prepareINT(text string) string {
	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.Split(v, ":")
			if strings.TrimSpace(vs[0]) == "organisation" {
				if token == "" {
					token = "registrant"
				}
			}
			if strings.TrimSpace(vs[0]) == "contact" {
				token = strings.TrimSpace(vs[1])
			} else {
				if token != "" {
					v = fmt.Sprintf("%s %s", token, v)
				}
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareKZ do prepare the .kz domain
func prepareKZ(text string) string {

	groupTokens := map[string]string{
		"Organization Using Domain Name": "Registrant ",
		"Administrative Contact/Agent":   "Administrative ",
	}

	topTokens := map[string]string{
		"Domain status": "Domain status : ",
	}

	tokens := map[string]string{
		"Primary server":   "name server",
		"Secondary server": "name server",
		"Current Registar": "Registrar Name",
	}

	groupToken := ""
	topToken := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)

		if v == "" {
			groupToken = ""
			continue
		}

		if token, ok := groupTokens[v]; ok {
			groupToken = token
			continue
		}

		if !strings.Contains(v, ":") {
			if topToken != "" {
				v = fmt.Sprintf("%s%s", topToken, v)
			} else {
				continue
			}
		}

		vs := strings.SplitN(v, ":", 2)

		key := strings.TrimSpace(strings.Replace(vs[0], ".", "", -1))
		key = fmt.Sprintf("%s%s", groupToken, key)

		if token, ok := tokens[key]; ok {
			key = token
		}

		value := vs[1]

		if token, ok := topTokens[key]; ok {
			topToken = token
		} else {
			topToken = ""
		}

		v = fmt.Sprintf("%s: %s", key, value)

		result += "\n" + v
	}

	return result
}

// prepareMO do prepare the .mo domain
func prepareMO(text string) string {
	tokens := map[string]string{
		"Registrant:":           "Registrant",
		"Admin Contact(s):":     "Admin",
		"Billing Contact(s):":   "Billing",
		"Technical Contact(s):": "Technical",
	}

	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if v[0] == '-' {
			continue
		}
		for _, s := range []string{"Record created on", "Record expires on"} {
			if strings.HasPrefix(v, s) {
				v = strings.Replace(v, s, s+":", 1)
			}
		}
		if _, ok := tokens[v]; ok {
			token = tokens[v]
		} else {
			if token != "" {
				v = fmt.Sprintf("%s %s", token, v)
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareHK do prepare the .hk domain
func prepareHK(text string) string {
	tokens := map[string]string{
		"Registrant Contact Information:":     "Registrant",
		"Administrative Contact Information:": "Admin",
		"Technical Contact Information:":      "Technical",
		"Name Servers Information:":           "Name Servers:",
	}

	dateTokens := []string{
		"Domain Name Commencement Date",
		"Expiry Date",
	}

	token := ""
	addressToken := false
	text = strings.Replace(text, "\n\n", "\n", -1)

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		field := ""
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			field = strings.TrimSpace(vs[0])
			if strings.Contains(field, "(") {
				field = strings.Split(field, "(")[0]
				v = fmt.Sprintf("%s: %s", field, vs[1])
			}
			addressToken = field == "Address"
			if field == "Registrar Contact Information" {
				re := regexp.MustCompile(`Email\:\s+([^\s]+)(\s+Hotline\:(.*))?`)
				m := re.FindStringSubmatch(vs[1])
				if len(m) == 4 {
					v = ""
					if m[1] != "" {
						v += "Registrar Contact Email: " + m[1] + "\n"
					}
					if m[3] != "" {
						v += "Registrar Contact Phone: " + m[3] + "\n"
					}
					v = strings.TrimSpace(v)
				}
			}
			if field == "Family name" {
				vv := strings.TrimSpace(vs[1])
				if vv != "" && vv != "." {
					result += " " + vv
				}
				continue
			}
		} else {
			if addressToken {
				result += ", " + v
				continue
			}
		}
		if _, ok := tokens[v]; ok {
			token = tokens[v]
		} else {
			if token != "" && !assert.IsContains(dateTokens, field) {
				v = fmt.Sprintf("%s %s", token, v)
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareTW do prepare the .tw domain
func prepareTW(text string) string { //nolint:cyclop
	tokens := map[string][]string{
		"Registrant:": {
			"Organization",
			"Organization",
			"Name,Email",
			"Phone",
			"Fax",
			"Address",
			"Address",
			"Address",
		},
		"Administrative Contact:": {
			"Name,Email",
			"Phone",
			"Fax",
		},
		"Technical Contact:": {
			"Name,Email",
			"Phone",
			"Fax",
		},
		"Contact:": {
			"Name",
			"Email",
		},
	}

	token := ""
	index := -1

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if token == "" && v == "" {
			continue
		}
		for _, s := range []string{"Record created on", "Record expires on"} {
			if strings.HasPrefix(v, s) {
				v = strings.Replace(v, s, s+":", 1)
			}
		}
		if strings.Contains(v, ":") {
			token = ""
			index = -1
		}
		if _, ok := tokens[v]; ok {
			token = v
		} else {
			if token == "" {
				result += "\n" + v
			} else {
				index++
				if index > len(tokens[token])-1 {
					continue
				}
				tokenName := token[:len(token)-1]
				// Organization may be one line or two lines
				if tokenName == "Registrant" && tokens[token][index] == "Organization" {
					if strings.Contains(v, "@") {
						// Organization one line, jump to next
						index++
					} else if index == 1 {
						// Organization two line, join it
						result = strings.TrimSpace(result)
						if !strings.HasSuffix(result, ":") {
							result += ", " + v
						} else {
							result += " " + v
						}
						continue
					}
				}
				// See testdata/noterror/tw_git.tw
				if tokenName == "Registrant" && tokens[token][index] != "Address" {
					if len(v) == 2 && strings.ToLower(v) != v {
						index = xslice.Index(tokens[token], "Address")
					}
				}
				indexName := tokens[token][index]
				if tokenName == "Contact" {
					tokenName = "Registrant Contact"
				}
				if strings.Contains(indexName, ",") {
					ins := strings.Split(indexName, ",")
					re := regexp.MustCompile(`(.*)\s+([^\s]+@[^\s]+)`)
					m := re.FindStringSubmatch(v)
					if len(m) == 3 {
						result += fmt.Sprintf("\n%s %s: %s", tokenName, ins[0], strings.TrimSpace(m[1]))
						result += fmt.Sprintf("\n%s %s: %s", tokenName, ins[1], strings.TrimSpace(m[2]))
					} else {
						result += fmt.Sprintf("\n%s %s: %s", tokenName, ins[0], strings.TrimSpace(v))
					}
					continue
				}
				result += fmt.Sprintf("\n%s %s: %s", tokenName, indexName, v)
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
			for _, kk := range keys(hdls) {
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
	tokens := map[string]string{
		"person": "Registrant Name",
		"e-mail": "Registrant Email",
		"org":    "Registrant Organization",
	}

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
		if vv, ok := tokens[strings.TrimSpace(vs[0])]; ok {
			v = fmt.Sprintf("%s: %s", vv, vs[1])
		} else if vs[0] == "nserver" {
			v = strings.Replace(v, ",", " ", -1)
		}
		result += v + "\n"
	}

	return result
}

// prepareJP do prepare the .jp domain
func prepareJP(text string) string {
	replacer := regexp.MustCompile(`\n\[(.+?)\][\ ]*(.+?)?`)
	text = replacer.ReplaceAllString(text, "\n$1: $2")

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
			vs := strings.SplitN(v, ":", 2)
			token = strings.TrimSpace(vs[0])
			if token == adminToken {
				prefixToken = "admin "
			}
			if strings.ToLower(token) == "registrant" {
				v = fmt.Sprintf("registrant name: %s", vs[1])
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

// prepareUK do prepare the .uk domain
func prepareUK(text string) string {
	tokens := map[string]string{
		"URL": "Registrar URL",
	}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if vv, ok := tokens[strings.TrimSpace(vs[0])]; ok {
				v = fmt.Sprintf("%s: %s", vv, vs[1])
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareKR do prepare the .kr domain
func prepareKR(text string) string {
	english := "# ENGLISH"
	tokens := map[string]string{
		"Administrative Contact(AC)": "Administrative Contact Name",
		"AC E-Mail":                  "Administrative Contact E-Mail",
		"AC Phone Number":            "Administrative Contact Phone Number",
		"Authorized Agency":          "Registrar Name",
		"Registrant":                 "Registrant Name",
	}

	pos := strings.Index(text, english)
	if pos != -1 {
		text = text[pos+len(english):]
	}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if v[0] == '\'' || v[0] == '-' {
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if vv, ok := tokens[strings.TrimSpace(vs[0])]; ok {
				v = fmt.Sprintf("%s: %s", vv, vs[1])
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareNZ do prepare the .nz domain
func prepareNZ(text string) string {
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if strings.HasPrefix(strings.TrimSpace(vs[0]), "ns_name_") {
				v = fmt.Sprintf("name server: %s", vs[1])
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareTK do prepare the .tk domain
func prepareTK(text string) string {
	tokens := map[string]string{
		"Domain name:":        "Domain",
		"Domain Nameservers:": "Nameservers",
		"Owner contact:":      "Registrant",
		"Admin contact:":      "Admin",
		"Billing contact:":    "Billing",
		"Tech contact:":       "Technical",
		"Organisation:":       "Registrant",
	}

	fields := map[string][]string{
		"Registrant": {
			"Organization",
			"Name",
			"Address",
			"Address",
			"Address",
			"Country",
		},
	}

	token := ""
	result := ""
	index := 0

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if _, ok := tokens[v]; ok {
			token = tokens[v]
			continue
		}
		if token == "Domain" && strings.Contains(v, " is ") {
			vv := strings.Split(v, " is ")
			v = fmt.Sprintf("Name: %s\nStatus: %s", vv[0], vv[1])
		} else if token == "Registrant" && !strings.Contains(v, ":") {
			v = fmt.Sprintf("%s: %s", fields[token][index], v)
			index++
		}
		if token != "" {
			if !strings.Contains(v, ":") {
				v = fmt.Sprintf("%s: %s", token, v)
			} else {
				v = fmt.Sprintf("%s %s", token, v)
			}
		}
		result += "\n" + strings.TrimSpace(v)
	}

	return result
}

// prepareNL do prepare the .nl domain
func prepareNL(text string) string {
	tokens := map[string][]string{
		"Reseller:": {
			"Name",
			"Address",
			"Address",
			"Address",
			"Address",
		},
		"Registrar:": {
			"Name",
			"Address",
			"Address",
			"Address",
			"Address",
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
				index++
			}
		}
	}

	return result
}

// prepareEU do prepare the .eu domain
func prepareEU(text string) string {
	tokens := map[string]string{
		"Registrant:":   "Registrant",
		"Technical:":    "Technical",
		"Registrar:":    "Registrar",
		"Onsite(s):":    "Onsite",
		"Name servers:": "Name servers",
	}

	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if _, ok := tokens[v]; ok {
			token = tokens[v]
			continue
		} else {
			if token != "" {
				if strings.Contains(v, ":") {
					v = fmt.Sprintf("%s %s", token, v)
				} else {
					if strings.HasPrefix(v, "Visit www.eurid.eu") {
						continue
					}
					v = fmt.Sprintf("%s: %s", token, v)
				}
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareBR do prepare the .br domain
func prepareBR(text string) string {
	hdlToken := "nic-hdl-br"
	tokens := map[string]string{
		"owner-c":   "registrant",
		"admin-c":   "admin",
		"tech-c":    "tech",
		"billing-c": "billing",
	}

	token := ""
	hdlMap := map[string]string{}

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if strings.TrimSpace(vs[0]) == hdlToken {
				token = strings.TrimSpace(vs[1])
				hdlMap[token] = ""
			}
		}
		if token != "" {
			hdlMap[token] += "\n" + v
		}
	}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if strings.TrimSpace(vs[0]) == "owner" {
				v = fmt.Sprintf("registrant organization: %s", vs[1])
			}
			if vv, ok := tokens[strings.TrimSpace(vs[0])]; ok {
				for _, tt := range strings.Split(hdlMap[strings.TrimSpace(vs[1])], "\n") {
					if strings.TrimSpace(tt) == "" {
						continue
					}
					result += fmt.Sprintf("\n%s %s", vv, tt)
				}
				continue
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareIR do prepare the .ir domain
func prepareIR(text string) string {
	hdlToken := "nic-hdl"
	tokens := map[string]string{
		"holder-c": "registrant",
		"admin-c":  "admin",
		"tech-c":   "tech",
		"bill-c":   "billing",
	}

	token := ""
	hdlMap := map[string]string{}

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			token = ""
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if strings.TrimSpace(vs[0]) == hdlToken {
				token = strings.TrimSpace(vs[1])
				hdlMap[token] = ""
			}
		}
		if token != "" {
			hdlMap[token] += "\n" + v
		}
	}

	result := ""
	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if vv, ok := tokens[strings.TrimSpace(vs[0])]; ok {
				for _, tt := range strings.Split(hdlMap[strings.TrimSpace(vs[1])], "\n") {
					if strings.TrimSpace(tt) == "" {
						continue
					}
					result += fmt.Sprintf("\n%s %s", vv, tt)
				}
				continue
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareFI do prepare the .fi domain
func prepareFI(text string) string {
	tokens := map[string]string{
		"Holder":    "Registrant",
		"Registrar": "Registrar",
		"Tech":      "Technical",
	}

	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if len(v) == 0 {
			continue
		}
		if v[0] == '>' {
			token = ""
		}
		if _, ok := tokens[v]; ok {
			token = tokens[v]
		} else {
			if strings.Contains(v, ":") {
				vv := strings.SplitN(v, ":", 2)
				vv[0] = strings.Trim(vv[0], ".")
				if token == "Registrar" && vv[0] == "registrar" {
					vv[0] = "name"
				}
				v = fmt.Sprintf("%s: %s", vv[0], vv[1])
			}
			if token != "" {
				v = fmt.Sprintf("%s %s", token, v)
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareRS do prepare the .rs domain
func prepareRS(text string) string {
	tokens := map[string]string{
		"Registrant":             "Registrant",
		"Administrative contact": "Administrative",
		"Technical contact":      "Technical",
	}

	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if len(v) == 0 {
			token = ""
			continue
		}
		if strings.Contains(v, ":") {
			vv := strings.SplitN(v, ":", 2)
			vv[0] = strings.TrimSpace(vv[0])
			if t, ok := tokens[vv[0]]; ok {
				token = t
			} else if token != "" {
				v = fmt.Sprintf("%s %s", token, v)
			}
		}
		result += "\n" + v
	}

	return result
}

// prepareEE do prepare the .ee domain
func prepareEE(text string) string {
	tokens := map[string]string{
		"Domain:":                 "Domain",
		"Registrar:":              "Registrar",
		"Registrant:":             "Registrant",
		"Administrative contact:": "Administrative",
		"Technical contact:":      "Technical",
		"Name servers:":           "",
	}

	token := ""
	result := ""

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if len(v) == 0 {
			token = ""
			continue
		}
		if t, ok := tokens[v]; ok {
			token = t
			continue
		} else {
			v = fmt.Sprintf("%s %s", token, v)
		}
		result += "\n" + strings.TrimSpace(v)
	}

	return result
}

// prepareCN do prepare the .cn domain
func prepareCN(text string) string {
	var result string

	for _, v := range strings.Split(text, "\n") {
		v = strings.TrimSpace(v)
		if strings.Contains(v, ":") {
			vs := strings.SplitN(v, ":", 2)
			if strings.ToLower(strings.TrimSpace(vs[0])) == "registrant" {
				vs[0] = "registrant name"
			}
			v = fmt.Sprintf("%s: %s", vs[0], vs[1])
		}
		result += "\n" + v
	}

	return result
}
