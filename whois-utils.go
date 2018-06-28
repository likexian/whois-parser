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
    "io/ioutil"
)

func ReadFile(file string) (str string, err error) {
    tmpResult, err := ioutil.ReadFile(file)
    if err != nil {
        return
    }
    return string(tmpResult), nil
}

func WriteFile(file string, data string) error {
    return ioutil.WriteFile(file, []byte(data), 0644)
}

func IsNotFound(data string) (result bool) {
    data = strings.ToLower(data)
    return strings.Contains(data, "no found") || strings.Contains(data, "no match") ||
        strings.Contains(data, "not found") || strings.Contains(data, "not match") ||
        strings.Contains(data, "no entries found") || strings.Contains(data, "no data found") ||
        strings.Contains(data, "not registered") || strings.Contains(data, "is free")
}

func TransferName(name string) (string) {
    name = strings.ToLower(name)
    name = strings.Replace(name, "-", " ", -1)
    name = strings.Replace(name, "]", "", -1)
    name = strings.Replace(name, "[", "", -1)
    name = strings.Replace(name, "_", " ", -1)
    name = strings.Replace(name, "\\", "/", -1)

    if strings.Contains(name, "(") {
        names := strings.Split(name, "(")
        name = names[0]
    }

    name = strings.Replace(name, "domain name", "domain", -1)

    name = strings.Replace(name, "domain ", "", -1)
    name = strings.Replace(name, "sponsoring ", "", -1)
    name = strings.Replace(name, "registry ", "", -1)
    name = strings.Replace(name, "information", "", -1)

    name = strings.Replace(name, " contact", "", -1)
    name = strings.Replace(name, " number", "", -1)

    name = strings.Replace(name, "registrar iana", "registrar", -1)
    name = strings.Replace(name, "registrar name", "registrar", -1)
    name = strings.Replace(name, "registrar organization", "registrar", -1)
    name = strings.Replace(name, "registrar registration", "registrar", -1)
    name = strings.Replace(name, "registrar whois", "whois", -1)
    name = strings.Replace(name, "registrar url", "referral url", -1)
    name = strings.Replace(name, "registrar registration", "registration", -1)
    name = strings.Replace(name, "authorized agency", "registrar", -1)

    name = strings.Replace(name, "host name", "name server", -1)
    name = strings.Replace(name, "nserver", "name server", -1)
    name = strings.Replace(name, "nameservers", "name server", -1)
    name = strings.Replace(name, "name servers", "name server", -1)
    name = strings.Replace(name, "dns server", "name server", -1)
    name = strings.Replace(name, "dns name server", "name server", -1)

    name = strings.Replace(name, " on", " date", -1)
    name = strings.Replace(name, " at", " date", -1)

    name = strings.Replace(name, "created", "create", -1)
    name = strings.Replace(name, "creation", "create", -1)
    name = strings.Replace(name, "registered date", "create date", -1)
    name = strings.Replace(name, "registration date", "create date", -1)
    name = strings.Replace(name, "domain created", "create", -1)
    name = strings.Replace(name, "domain registered", "create", -1)
    name = strings.Replace(name, "commencement date", "create", -1)
    name = strings.Replace(name, "create date", "create", -1)
    name = strings.Replace(name, "created on", "create", -1)

    name = strings.Replace(name, "updated", "update", -1)
    name = strings.Replace(name, "modified", "update", -1)
    name = strings.Replace(name, "changed", "update", -1)
    name = strings.Replace(name, "last update", "update", -1)
    name = strings.Replace(name, "domain updated", "update", -1)
    name = strings.Replace(name, "update date", "update", -1)

    name = strings.Replace(name, "expires", "expire", -1)
    name = strings.Replace(name, "paid till", "expire", -1)
    name = strings.Replace(name, "expiration", "expire", -1)
    name = strings.Replace(name, "expiry", "expire", -1)
    name = strings.Replace(name, "registrar expire", "expire", -1)
    name = strings.Replace(name, "domain expires", "expire", -1)
    name = strings.Replace(name, "expire date", "expire", -1)
    name = strings.Replace(name, "expire time", "expire", -1)

    name = strings.Replace(name, "owner", "registrant", -1)
    name = strings.Replace(name, "administrative", "admin", -1)
    name = strings.Replace(name, "technical", "tech", -1)
    name = strings.Replace(name, "billing", "bill", -1)

    name = strings.Replace(name, "address1", "street", -1)
    name = strings.Replace(name, "address2", "street_ext", -1)
    name = strings.Replace(name, "street1", "street", -1)
    name = strings.Replace(name, "street2", "street_ext", -1)
    name = strings.Replace(name, "state/", "", -1)
    name = strings.Replace(name, "/economy", "", -1)

    name = strings.Replace(name, "state", "status", -1)
    name = strings.Replace(name, "facsimile", "fax", -1)

    name = strings.Replace(name, "registration status", "status", -1)
    name = strings.Replace(name, "e mail", "email", -1)

    name = strings.Replace(name, "  ", " ", -1)
    name = strings.Trim(name, " ")

    if name == "admin c" {
        name = "admin"
    }
    if name == "tech c" {
        name = "tech"
    }
    if name == "bill c" {
        name = "bill"
    }

    return name
}

func RemoveDuplicateField(data string) string {
    var newFields []string
    for _, v := range strings.Split(data, ",") {
        if v == "" {
            continue
        }
        if !StringInArray(newFields, v) {
            newFields = append(newFields, v)
        }
    }
    return strings.Join(newFields, ",")
}

func StringInArray(array []string, find string) bool {
    for _, v := range array {
        if v == find {
            return true
        }
    }
    return false
}

func FixNameServers(nservers string) string {
    servers := strings.Split(nservers, ",")
    for k, v := range servers {
        names := strings.Split(strings.Trim(v, " "), " ")
        servers[k] = names[0]
    }
    return strings.Join(servers, ",")
}
