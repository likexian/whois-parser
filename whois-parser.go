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

var DomainNotFoundError = errors.New("Domain is not found.")
var DomainInvalidDataError = errors.New("Domain whois data invalid.")
var DomainLimitExceededError = errors.New("Your connection limit exceeded.")

var replacer = strings.NewReplacer(
    "\r", "",
    // Replace ":" for .jp domains, example string:
    // [Name Server]           ns1.voodoo.com
    "]           ", ":",
)

func Parse(text string) (wi WhoisInfo, err error) {

    if len(text) < 100 {
        if IsNotFound(text) {
            return wi, DomainNotFoundError
        } else {
            return wi, DomainInvalidDataError
        }
    }

    whoisLines := strings.Split(replacer.Replace(text), "\n")
    for i:=0; i<len(whoisLines); i++ {
        line := strings.Trim(whoisLines[i], " ")
        if len(line) < 5 || !strings.Contains(line, ":") {
            continue
        }

        fChar := line[:1]
        if fChar == ">" || fChar == "%" || fChar == "*" {
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
        value = strings.TrimSpace(lines[1])
        if value == "" {
            continue
        }

        name = TransferName(name)
        switch {
        // Parse registrar
        case name == "domain":
            wi.Registrar.DomainName = value
        case name == "id" || name == "roid":
            wi.Registrar.DomainId = value
        case name == "registrar id":
            wi.Registrar.RegistrarID = value
        case name == "registrar":
            wi.Registrar.RegistrarName = value
        case name == "whois server":
            wi.Registrar.WhoisServer = value
        case name == "dnssec":
            wi.Registrar.DomainDNSSEC = value
        case name == "create":
            wi.Registrar.CreatedDate = value
        case name == "update":
            wi.Registrar.UpdatedDate = value
        case name == "expire":
            wi.Registrar.ExpirationDate = value
        case name == "name server":
            wi.Registrar.NameServers += strings.Trim(value, ".") + ","
        case name == "status":
            wi.Registrar.DomainStatus += value + ","
        case name == "referral url":
            wi.Registrar.ReferralURL = value

		// Parse registrant
        case strings.Contains(name, "registrant id"):
            wi.Registrant.ID = value
		case len(name) >= 10 && name[:10] == "registrant":
			name = strings.Trim(name[10:], " ")
			wi.Registrant = parserRegistrant(wi.Registrant, name, value)

		// Parse admin
        case strings.Contains(name, "admin id"):
            wi.Admin.ID = value
		case len(name) >= 5 && name[:5] == "admin":
			name = strings.Trim(name[5:], " ")
			wi.Admin = parserRegistrant(wi.Admin, name, value)

		// Parse tech
        case strings.Contains(name, "tech id"):
            wi.Tech.ID = value
        case len(name) >= 4 && name[:4] == "tech":
            name = strings.Trim(name[4:], " ")
            wi.Tech = parserRegistrant(wi.Tech, name, value)

		// Parse bill
		case strings.Contains(name, "bill id"):
			wi.Bill.ID = value
		case len(name) >= 4 && name[:4] == "bill":
            name = strings.Trim(name[4:], " ")
            wi.Bill = parserRegistrant(wi.Bill, name, value)
        default:
            wi.Registrant = parserRegistrant(wi.Registrant, name, value)
        }
    }

    // Post processing NameServers, DomainStatuses
    wi.Registrar.NameServers = FixNameServers(RemoveDuplicateField(strings.ToLower(wi.Registrar.NameServers)))
    wi.Registrar.DomainStatus = RemoveDuplicateField(strings.ToLower(wi.Registrar.DomainStatus))

    return wi, nil
}


func parserRegistrant(registrant Registrant, name, value string) (Registrant) {
    switch name {
    case "name", "":
        registrant.Name = value
    case "organization", "org":
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
