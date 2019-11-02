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

// WhoisInfo storing domain whois info
type WhoisInfo struct {
	Domain         Domain  `json:"domain"`
	Registrar      Contact `json:"registrar"`
	Registrant     Contact `json:"registrant"`
	Administrative Contact `json:"administrative"`
	Technical      Contact `json:"technical"`
	Billing        Contact `json:"billing"`
}

// Domain storing domain name info
type Domain struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	Name           string `json:"name"`
	Extension      string `json:"extension"`
	Status         string `json:"status"`
	DNSSEC         string `json:"dnssec"`
	WhoisServer    string `json:"whois_server"`
	NameServers    string `json:"name_servers"`
	CreatedDate    string `json:"created_date"`
	UpdatedDate    string `json:"updated_date"`
	ExpirationDate string `json:"expiration_date"`
}

// Contact storing domain contact info
type Contact struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street       string `json:"street"`
	City         string `json:"city"`
	Province     string `json:"province"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	Phone        string `json:"phone"`
	PhoneExt     string `json:"phone_ext"`
	Fax          string `json:"fax"`
	FaxExt       string `json:"fax_ext"`
	Email        string `json:"email"`
	ReferralURL  string `json:"referral_url"`
}
