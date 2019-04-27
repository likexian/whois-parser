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

// WhoisInfo storing main info
type WhoisInfo struct {
	Registrar  Registrar  `json:"registrar"`
	Registrant Registrant `json:"registrant"`
	Admin      Registrant `json:"admin"`
	Tech       Registrant `json:"tech"`
	Bill       Registrant `json:"bill"`
}

// Registrar storing registrar info
type Registrar struct {
	RegistrarID    string `json:"registrar_id"`
	RegistrarName  string `json:"registrar_name"`
	WhoisServer    string `json:"whois_server"`
	ReferralURL    string `json:"referral_url"`
	DomainId       string `json:"domain_id"`
	DomainName     string `json:"domain_name"`
	DomainStatus   string `json:"domain_status"`
	NameServers    string `json:"name_servers"`
	DomainDNSSEC   string `json:"domain_dnssec"`
	CreatedDate    string `json:"created_date"`
	UpdatedDate    string `json:"updated_date"`
	ExpirationDate string `json:"expiration_date"`
}

// Registrant storing registrant info
type Registrant struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street       string `json:"street"`
	StreetExt    string `json:"street_ext"`
	City         string `json:"city"`
	Province     string `json:"province"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	Phone        string `json:"phone"`
	PhoneExt     string `json:"phone_ext"`
	Fax          string `json:"fax"`
	FaxExt       string `json:"fax_ext"`
	Email        string `json:"email"`
}
