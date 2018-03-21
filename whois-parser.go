/*
 * Go module for whois info parser
 * https://www.likexian.com/
 *
 * Copyright 2014-2018, Li Kexian
 * Released under the Apache License, Version 2.0
 *
 */

package whois_parser


import (
    "strings"
	"errors"
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

var DomainNotFoundError = errors.New("Domain is not found.")
var DomainInvalidDataError = errors.New("Domain whois data invalid.")

func Parse(whois string) (WhoisInfo, error) {
    if len(whois) < 100 {
        if IsNotFound(whois) {
            return WhoisInfo{}, DomainNotFoundError
        } else {
            return WhoisInfo{}, DomainInvalidDataError
        }
    }

    var registrar Registrar
    var registrant Registrant
    var admin Registrant
    var tech Registrant
    var bill Registrant

    whoisText := strings.Replace(whois, "\r", "", -1)

    // Replace ":" for .jp domains, example string:
	// [Name Server]           ns1.voodoo.com
	whoisText = strings.Replace(whois, "]           ", ":", -1)
	whoisLines := strings.Split(whoisText, "\n")

    for i:=0; i<len(whoisLines); i++ {
        line := strings.Trim(whoisLines[i], " ")
        if len(line) < 5 || !strings.Contains(line, ":") {
            continue
        }

        fchar := line[:1]
        if fchar == ">" || fchar == "%" || fchar == "*" {
            continue
        }

        if line[len(line) - 1:] == ":" {
            i += 1
            for ; i<len(whoisLines); i++ {
                thisLine := strings.Trim(whoisLines[i], " ")
                if strings.Contains(thisLine, ":") {
                    break
                }
                line += thisLine + ","
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
        switch {
        // Parse registrar
        case name == "domain":
            registrar.DomainName = value
        case name == "id" || name == "roid":
            registrar.DomainId = value
        case name == "registrar id":
            registrar.RegistrarID = value
        case name == "registrar":
            registrar.RegistrarName = value
        case name == "whois server":
            registrar.WhoisServer = value
        case name == "dnssec":
            registrar.DomainDNSSEC = value
        case name == "create":
            registrar.CreatedDate = value
        case name == "update":
            registrar.UpdatedDate = value
        case name == "expire":
            registrar.ExpirationDate = value
        case name == "name server":
            registrar.NameServers += strings.Trim(value, ".") + ","
        case name == "status":
            registrar.DomainStatus += value + ","
        case name == "referral url":
            registrar.ReferralURL = value

		// Parse registrant
        case strings.Contains(name, "registrant id"):
            registrant.ID = value
		case len(name) >= 10 && name[:10] == "registrant":
			name = strings.Trim(name[10:], " ")
			registrant = parserRegistrant(registrant, name, value)

		// Parse admin
        case strings.Contains(name, "admin id"):
            admin.ID = value
		case len(name) >= 5 && name[:5] == "admin":
			name = strings.Trim(name[5:], " ")
			admin = parserRegistrant(admin, name, value)

		// Parse tech
        case strings.Contains(name, "tech id"):
            tech.ID = value
        case len(name) >= 4 && name[:4] == "tech":
            name = strings.Trim(name[4:], " ")
            tech = parserRegistrant(tech, name, value)

		// Parse bill
		case strings.Contains(name, "bill id"):
			bill.ID = value
		case len(name) >= 4 && name[:4] == "bill":
            name = strings.Trim(name[4:], " ")
            bill = parserRegistrant(bill, name, value)
        }
    }

    registrar.NameServers = RemoveDuplicateField(strings.ToLower(registrar.NameServers))
    registrar.DomainStatus = RemoveDuplicateField(strings.ToLower(registrar.DomainStatus))
    registrar.NameServers = FixNameServers(registrar.NameServers)

    return WhoisInfo{
        Registrar: registrar,
        Registrant: registrant,
        Admin: admin,
        Tech: tech,
        Bill: bill,
    }, nil
}


func parserRegistrant(registrant Registrant, name, value string) (Registrant) {
    switch name {
    case "name", "":
        registrant.Name = value
    case "organization":
        registrant.Organization = value
    case "street":
        registrant.Street = value
    case "street ext":
        registrant.StreetExt = value
    case "city":
        registrant.City = value
    case "province":
        registrant.Province = value
    case "postal code":
        registrant.PostalCode = value
    case "country":
        registrant.Country = value
    case "phone":
        registrant.Phone = value
    case "phone ext":
        registrant.PhoneExt = value
    case "fax":
        registrant.Fax = value
    case "fax ext":
        registrant.FaxExt = value
    case "email":
        registrant.Email = strings.ToLower(value)
    }

    return registrant
}
