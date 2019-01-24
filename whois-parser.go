/*
 * Go module for whois info parser
 * https://www.likexian.com/
 *
 * Copyright 2014-2019, Li Kexian
 * Released under the Apache License, Version 2.0
 *
 */

package whois_parser


import (
    "fmt"
    "strings"
)


type WhoisInfo struct {
    Registrar  Registrar  `json:"registrar"`
    Registrant Registrant `json:"registrant"`
    Admin      Registrant `json:"admin"`
    Tech       Registrant `json:"tech"`
    Bill       Registrant `json:"bill"`
}


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


func Parser(whois string) (whois_info WhoisInfo, err error) {
    if len(whois) < 100 {
        if IsNotFound(whois) {
            err = fmt.Errorf("Domain is not found.")
        } else {
            err = fmt.Errorf("Domain whois data invalid.")
        }
        return
    }

    var registrar Registrar
    var registrant Registrant
    var admin Registrant
    var tech Registrant
    var bill Registrant

    whois_text := strings.Replace(whois, "\r", "", -1)
    whois_lines := strings.Split(whois_text, "\n")

    for i:=0; i<len(whois_lines); i++ {
        line := strings.TrimSpace(whois_lines[i])
        if len(line) < 5 || !strings.Contains(line, ":") {
            continue
        }

        fchar := line[:1]
        if fchar == ">" || fchar == "%" || fchar == "*" {
            continue
        }

        if line[len(line) - 1:] == ":" {
            i += 1
            for ; i<len(whois_lines); i++ {
                this_line := strings.TrimSpace(whois_lines[i])
                if strings.Contains(this_line, ":") {
                    break
                }
                line += this_line + ","
            }
            line = strings.Trim(line, ",")
            i -= 1
        }

        lines := strings.SplitN(line, ":", 2)
        name := strings.TrimSpace(lines[0])
        value := strings.TrimSpace(lines[1])
        if value == "" {
            continue
        }

        key_name := FindKeyName(name)
        switch key_name {
            case "domain_id":
                registrar.DomainId = value
            case "domain_name":
                registrar.DomainName = value
            case "registrar_id":
                if registrar.RegistrarID == "" {
                    registrar.RegistrarID = value
                }
            case "registrar_name":
                if registrar.RegistrarName == "" {
                    registrar.RegistrarName = value
                }
            case "whois_server":
                if registrar.WhoisServer == "" {
                    registrar.WhoisServer = value
                }
            case "referral_url":
                if registrar.ReferralURL == "" {
                    registrar.ReferralURL = value
                }
            case "domain_status":
                registrar.DomainStatus += value + ","
            case "name_servers":
                registrar.NameServers += value + ","
            case "domain_dnssec":
                if registrar.DomainDNSSEC == "" {
                    registrar.DomainDNSSEC = value
                }
            case "created_date":
                if registrar.CreatedDate == "" {
                    registrar.CreatedDate = value
                }
            case "updated_date":
                if registrar.UpdatedDate == "" {
                    registrar.UpdatedDate = value
                }
            case "expired_date":
                if registrar.ExpirationDate == "" {
                    registrar.ExpirationDate = value
                }
            case "registrant_id":
                registrant.ID = value
            case "admin_id":
                admin.ID = value
            case "tech_id":
                tech.ID = value
            case "bill_id":
                bill.ID = value
            default:
                name = ClearName(name)
                if !strings.Contains(name, " ") {
                    name += " name"
                }
                ns := strings.SplitN(name, " ", 2)
                name = strings.TrimSpace("registrant " + ns[1])
                if ns[0] == "registrant" {
                    registrant = parser_registrant(registrant, name, value)
                } else if ns[0] == "admin" || ns[0] == "administrative" {
                    admin = parser_registrant(admin, name, value)
                } else if ns[0] == "tech" || ns[0] == "technical" {
                    tech = parser_registrant(tech, name, value)
                } else if ns[0] == "bill" || ns[0] == "billing" {
                    bill = parser_registrant(bill, name, value)
                }
        }
    }

    registrar.NameServers = RemoveDuplicateField(strings.ToLower(registrar.NameServers))
    registrar.DomainStatus = RemoveDuplicateField(strings.ToLower(registrar.DomainStatus))
    registrar.NameServers = FixNameServers(registrar.NameServers)

    whois_info.Registrar = registrar
    whois_info.Registrant = registrant
    whois_info.Admin = admin
    whois_info.Tech = tech
    whois_info.Bill = bill

    return
}


func parser_registrant(registrant Registrant, name, value string) (Registrant) {
    key_name := FindKeyName(name)
    switch key_name {
        case "registrant_id":
            registrant.ID = value
        case "registrant_name":
            registrant.Name = value
        case "registrant_organization":
            registrant.Organization = value
        case "registrant_street":
            registrant.Street = value
        case "registrant_city":
            registrant.City = value
        case "registrant_state_province":
            registrant.Province = value
        case "registrant_postal_code":
            registrant.PostalCode = value
        case "registrant_country":
            registrant.Country = value
        case "registrant_phone":
            registrant.Phone = value
        case "registrant_phone_ext":
            registrant.PhoneExt = value
        case "registrant_fax":
            registrant.Fax = value
        case "registrant_fax_ext":
            registrant.FaxExt = value
        case "registrant_email":
            registrant.Email = strings.ToLower(value)
    }

    return registrant
}
