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
    "io/ioutil"
    "testing"
    "runtime"
)


func assertNotError(t *testing.T, err error) {
    if err != nil {
        _, file, line, _ := runtime.Caller(1)
        t.Errorf("%s:%d", file, line)
        t.Errorf(err.Error())
        t.FailNow()
    }
}


func assertHasError(t *testing.T, err error) {
    if err == nil {
        _, file, line, _ := runtime.Caller(1)
        t.Errorf("%s:%d", file, line)
        t.Errorf("Error shall not equal nil")
        t.FailNow()
    }
}


func assertStringEqual(t *testing.T, a, b string) {
    if a != b {
        _, file, line, _ := runtime.Caller(1)
        t.Errorf("%s:%d", file, line)
        t.Errorf("%s != %s", a, b)
        t.FailNow()
    }
}


func assertNotEmpty(t *testing.T, a string) {
    if a == "" {
        _, file, line, _ := runtime.Caller(1)
        t.Errorf("%s:%d", file, line)
        t.Errorf("Result shall not be empty")
        t.FailNow()
    }
}


func TestWhoisParser(t *testing.T) {
    _, err := Parse("not found")
    assertHasError(t, err)
    assertStringEqual(t, fmt.Sprintf("%s", err), "Domain is not found.")

    _, err = Parse("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
    assertHasError(t, err)
    assertStringEqual(t, fmt.Sprintf("%s", err), "Domain query limit exceeded.")

    _, err = Parse("Hello - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
    assertHasError(t, err)
    assertStringEqual(t, fmt.Sprintf("%s", err), "Domain whois data invalid.")

    dirs, err := ioutil.ReadDir("./examples/")
    assertNotError(t, err)

    for _, v := range dirs {
        domain := v.Name()
        domain_ext := domain[strings.LastIndex(domain, ".") + 1:]
        whois_raw, err := ReadFile("./examples/" + domain)
        assertNotError(t, err)

        if domain[len(domain) - 4:] == ".out" {
            continue
        }

        whois_info, err := Parse(whois_raw)

        if domain == "mjj.com" {
            assertNotEmpty(t, whois_info.Registrar.RegistrarID)
        }

        if domain_ext != "museum" && domain_ext != "at" && domain_ext != "int" && domain_ext != "jp" {
            assertNotEmpty(t, whois_info.Registrar.RegistrarName)
        }
        if domain_ext == "com" {
            assertNotEmpty(t, whois_info.Registrar.WhoisServer)
        }
        if domain_ext == "com" {
            assertNotEmpty(t, whois_info.Registrar.ReferralURL)
        }
        if domain == "mjj.com" {
            assertNotEmpty(t, whois_info.Registrar.DomainId)
        }

        assertNotEmpty(t, whois_info.Registrar.DomainName)
        if domain_ext != "at" && domain_ext != "kr" && domain_ext != "int" {
            assertNotEmpty(t, whois_info.Registrar.DomainStatus)
        }
        if domain_ext != "au" && domain_ext != "at" && domain_ext != "int" && domain_ext != "jp" {
            assertNotEmpty(t, whois_info.Registrar.CreatedDate)
        }
        if domain_ext != "cn" && domain_ext != "ru" && domain_ext != "su" && domain_ext != "hk" {
            assertNotEmpty(t, whois_info.Registrar.UpdatedDate)
        }
        if domain_ext != "au" && domain_ext != "at" && domain_ext != "re" && domain_ext != "fr" && domain_ext != "int" {
            assertNotEmpty(t, whois_info.Registrar.ExpirationDate)
        }
        assertNotEmpty(t, whois_info.Registrar.NameServers)
        if domain_ext == "cn" {
            assertNotEmpty(t, whois_info.Registrar.DomainDNSSEC)
        }

        content := ""
        content += fmt.Sprintf("registrar_id: %s\n", whois_info.Registrar.RegistrarID)
        content += fmt.Sprintf("registrar_name: %s\n", whois_info.Registrar.RegistrarName)
        content += fmt.Sprintf("whois_server: %s\n", whois_info.Registrar.WhoisServer)
        content += fmt.Sprintf("referral_url: %s\n", whois_info.Registrar.ReferralURL)
        content += fmt.Sprintf("domain_id: %s\n", whois_info.Registrar.DomainId)
        content += fmt.Sprintf("domain_name: %s\n", whois_info.Registrar.DomainName)
        content += fmt.Sprintf("domain_status: %s\n", whois_info.Registrar.DomainStatus)
        content += fmt.Sprintf("created_date: %s\n", whois_info.Registrar.CreatedDate)
        content += fmt.Sprintf("updated_date: %s\n", whois_info.Registrar.UpdatedDate)
        content += fmt.Sprintf("expiration_date: %s\n", whois_info.Registrar.ExpirationDate)
        content += fmt.Sprintf("name_servers: %s\n", whois_info.Registrar.NameServers)
        content += fmt.Sprintf("domain_dnssec: %s\n", whois_info.Registrar.DomainDNSSEC)

        content += fmt.Sprintf("\nregistrant\n")
        content += fmt.Sprintf("id: %s\n", whois_info.Registrant.ID)
        content += fmt.Sprintf("name: %s\n", whois_info.Registrant.Name)
        content += fmt.Sprintf("organization: %s\n", whois_info.Registrant.Organization)
        content += fmt.Sprintf("street: %s\n", whois_info.Registrant.Street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.Registrant.StreetExt)
        content += fmt.Sprintf("city: %s\n", whois_info.Registrant.City)
        content += fmt.Sprintf("province: %s\n", whois_info.Registrant.Province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.Registrant.PostalCode)
        content += fmt.Sprintf("country: %s\n", whois_info.Registrant.Country)
        content += fmt.Sprintf("phone: %s\n", whois_info.Registrant.Phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.Registrant.PhoneExt)
        content += fmt.Sprintf("fax: %s\n", whois_info.Registrant.Fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.Registrant.FaxExt)
        content += fmt.Sprintf("email: %s\n", whois_info.Registrant.Email)

        content += fmt.Sprintf("\nadmin\n")
        content += fmt.Sprintf("id: %s\n", whois_info.Admin.ID)
        content += fmt.Sprintf("name: %s\n", whois_info.Admin.Name)
        content += fmt.Sprintf("organization: %s\n", whois_info.Admin.Organization)
        content += fmt.Sprintf("street: %s\n", whois_info.Admin.Street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.Admin.StreetExt)
        content += fmt.Sprintf("city: %s\n", whois_info.Admin.City)
        content += fmt.Sprintf("province: %s\n", whois_info.Admin.Province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.Admin.PostalCode)
        content += fmt.Sprintf("country: %s\n", whois_info.Admin.Country)
        content += fmt.Sprintf("phone: %s\n", whois_info.Admin.Phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.Admin.PhoneExt)
        content += fmt.Sprintf("fax: %s\n", whois_info.Admin.Fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.Admin.FaxExt)
        content += fmt.Sprintf("email: %s\n", whois_info.Admin.Email)

        content += fmt.Sprintf("\ntech\n")
        content += fmt.Sprintf("id: %s\n", whois_info.Tech.ID)
        content += fmt.Sprintf("name: %s\n", whois_info.Tech.Name)
        content += fmt.Sprintf("organization: %s\n", whois_info.Tech.Organization)
        content += fmt.Sprintf("street: %s\n", whois_info.Tech.Street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.Tech.StreetExt)
        content += fmt.Sprintf("city: %s\n", whois_info.Tech.City)
        content += fmt.Sprintf("province: %s\n", whois_info.Tech.Province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.Tech.PostalCode)
        content += fmt.Sprintf("country: %s\n", whois_info.Tech.Country)
        content += fmt.Sprintf("phone: %s\n", whois_info.Tech.Phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.Tech.PhoneExt)
        content += fmt.Sprintf("fax: %s\n", whois_info.Tech.Fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.Tech.FaxExt)
        content += fmt.Sprintf("email: %s\n", whois_info.Tech.Email)

        content += fmt.Sprintf("\nbill\n")
        content += fmt.Sprintf("id: %s\n", whois_info.Bill.ID)
        content += fmt.Sprintf("name: %s\n", whois_info.Bill.Name)
        content += fmt.Sprintf("organization: %s\n", whois_info.Bill.Organization)
        content += fmt.Sprintf("street: %s\n", whois_info.Bill.Street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.Bill.StreetExt)
        content += fmt.Sprintf("city: %s\n", whois_info.Bill.City)
        content += fmt.Sprintf("province: %s\n", whois_info.Bill.Province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.Bill.PostalCode)
        content += fmt.Sprintf("country: %s\n", whois_info.Bill.Country)
        content += fmt.Sprintf("phone: %s\n", whois_info.Bill.Phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.Bill.PhoneExt)
        content += fmt.Sprintf("fax: %s\n", whois_info.Bill.Fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.Bill.FaxExt)
        content += fmt.Sprintf("email: %s\n", whois_info.Bill.Email)

        WriteFile("./examples/" + v.Name() + ".out", content)
    }
}
