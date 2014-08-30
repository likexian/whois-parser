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
    registrar Registrar
    registrant Registrant
    admin Registrant
    tech Registrant
    bill Registrant
}


type Registrar struct {
    registrar_id string
    registrar_name string
    whois_server string
    referral_url string
    domain_id string
    domain_name string
    domain_status string
    name_servers string
    domain_dnssec string
    created_date string
    updated_date string
    expiration_date string
}


type Registrant struct {
    id string
    name string
    organization string
    street string
    street_ext string
    city string
    province string
    postal_code string
    country string
    phone string
    phone_ext string
    fax string
    fax_ext string
    email string
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
            registrar.domain_name = value
        } else if (name == "id" || name == "roid") {
            registrar.domain_id = value
        } else if (name == "registrar id") {
            registrar.registrar_id = value
        } else if (name == "registrar") {
            registrar.registrar_name = value
        } else if (name == "whois server") {
            registrar.whois_server = value
        } else if (name == "dnssec") {
            registrar.domain_dnssec = value
        } else if (name == "create") {
            registrar.created_date = value
        } else if (name == "update") {
            registrar.updated_date = value
        } else if (name == "expire") {
            registrar.expiration_date = value
        } else if (name == "name server") {
            registrar.name_servers += strings.Trim(value, ".") + ","
        } else if (name == "status") {
            registrar.domain_status += value + ","
        } else if (name == "referral url") {
            registrar.referral_url = value
        } else if strings.Contains(name, "registrant id") {
            registrant.id = value
        } else if strings.Contains(name, "admin id") {
            admin.id = value
        } else if strings.Contains(name, "tech id") {
            tech.id = value
        } else if strings.Contains(name, "bill id") {
            bill.id = value
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

    registrar.name_servers = RemoveDuplicateField(strings.ToLower(registrar.name_servers))
    registrar.domain_status = RemoveDuplicateField(strings.ToLower(registrar.domain_status))
    registrar.name_servers = FixNameServers(registrar.name_servers)

    whois_info.registrar = registrar
    whois_info.registrant = registrant
    whois_info.admin = admin
    whois_info.tech = tech
    whois_info.bill = bill

    return
}


func parser_registrant(registrant Registrant, name, value string) (Registrant) {
    if name == "name" || name == "" {
        registrant.name = value
    } else if name == "organization" {
        registrant.organization = value
    } else if name == "street" {
        registrant.street = value
    } else if name == "street ext" {
        registrant.street_ext = value
    } else if name == "city" {
        registrant.city = value
    } else if name == "province" {
        registrant.province = value
    } else if name == "postal code" {
        registrant.postal_code = value
    } else if name == "country" {
        registrant.country = value
    } else if name == "phone" {
        registrant.phone = value
    } else if name == "phone ext" {
        registrant.phone_ext = value
    } else if name == "fax" {
        registrant.fax = value
    } else if name == "fax ext" {
        registrant.fax_ext = value
    } else if name == "email" {
        registrant.email = strings.ToLower(value)
    }

    return registrant
}
