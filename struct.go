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

// WhoisInfo storing domain whois info
type WhoisInfo struct {
	Domain         *Domain  `json:"domain,omitempty"`
	Registrar      *Contact `json:"registrar,omitempty"`
	Registrant     *Contact `json:"registrant,omitempty"`
	Administrative *Contact `json:"administrative,omitempty"`
	Technical      *Contact `json:"technical,omitempty"`
	Billing        *Contact `json:"billing,omitempty"`
}

// Domain storing domain name info
type Domain struct {
	ID             string   `json:"id,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	Punycode       string   `json:"punycode,omitempty"`
	Name           string   `json:"name,omitempty"`
	Extension      string   `json:"extension,omitempty"`
	WhoisServer    string   `json:"whois_server,omitempty"`
	Status         []string `json:"status,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
	DNSSec         bool     `json:"dnssec,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
}

// Contact storing domain contact info
type Contact struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Street       string `json:"street,omitempty"`
	City         string `json:"city,omitempty"`
	Province     string `json:"province,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Phone        string `json:"phone,omitempty"`
	PhoneExt     string `json:"phone_ext,omitempty"`
	Fax          string `json:"fax,omitempty"`
	FaxExt       string `json:"fax_ext,omitempty"`
	Email        string `json:"email,omitempty"`
	ReferralURL  string `json:"referral_url,omitempty"`
}
