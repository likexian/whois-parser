/*
 * Go module for whois info parser
 * http://www.likexian.com/
 *
 * Copyright 2014, Kexian Li
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
        line := strings.Trim(whois_lines[i], " ")
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
                this_line := strings.Trim(whois_lines[i], " ")
                if strings.Contains(this_line, ":") {
                    break
                }
                line += this_line + ","
            }
            line = strings.Trim(line, ",")
            i -= 1
        }

        lines := strings.SplitN(line, ":", 2)
        name := strings.Trim(lines[0], " ")
        value := strings.Trim(lines[1], " ")
        if value == "" {
            continue
        }

        name = TransferName(name)
        if (name == "domain") {
            registrar.DomainName = value
        } else if (name == "id" || name == "roid") {
            registrar.DomainId = value
        } else if (name == "registrar id") {
            registrar.RegistrarID = value
        } else if (name == "registrar") {
            registrar.RegistrarName = value
        } else if (name == "whois server") {
            registrar.WhoisServer = value
        } else if (name == "dnssec") {
            registrar.DomainDNSSEC = value
        } else if (name == "create") {
            registrar.CreatedDate = value
        } else if (name == "update") {
            registrar.UpdatedDate = value
        } else if (name == "expire") {
            registrar.ExpirationDate = value
        } else if (name == "name server") {
            registrar.NameServers += strings.Trim(value, ".") + ","
        } else if (name == "status") {
            registrar.DomainStatus += value + ","
        } else if (name == "referral url") {
            registrar.ReferralURL = value
        } else if strings.Contains(name, "registrant id") {
            registrant.ID = value
        } else if strings.Contains(name, "admin id") {
            admin.ID = value
        } else if strings.Contains(name, "tech id") {
            tech.ID = value
        } else if strings.Contains(name, "bill id") {
            bill.ID = value
        } else if (len(name) >= 10 && name[:10] == "registrant") {
            name = strings.Trim(name[10:], " ")
            registrant = parser_registrant(registrant, name, value)
        } else if (len(name) >= 5 && name[:5] == "admin") {
            name = strings.Trim(name[5:], " ")
            admin = parser_registrant(admin, name, value)
        } else if (len(name) >= 4 && name[:4] == "tech") {
            name = strings.Trim(name[4:], " ")
            tech = parser_registrant(tech, name, value)
        } else if (len(name) >= 4 && name[:4] == "bill") {
            name = strings.Trim(name[4:], " ")
            bill = parser_registrant(bill, name, value)
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
    if name == "name" || name == "" {
        registrant.Name = value
    } else if name == "organization" {
        registrant.Organization = value
    } else if name == "street" {
        registrant.Street = value
    } else if name == "street ext" {
        registrant.StreetExt = value
    } else if name == "city" {
        registrant.City = value
    } else if name == "province" {
        registrant.Province = value
    } else if name == "postal code" {
        registrant.PostalCode = value
    } else if name == "country" {
        registrant.Country = value
    } else if name == "phone" {
        registrant.Phone = value
    } else if name == "phone ext" {
        registrant.PhoneExt = value
    } else if name == "fax" {
        registrant.Fax = value
    } else if name == "fax ext" {
        registrant.FaxExt = value
    } else if name == "email" {
        registrant.Email = strings.ToLower(value)
    }

    return registrant
}
