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
    "io/ioutil"
    "testing"
    "github.com/bmizerany/assert"
)


func TestWhoisParser(t *testing.T) {
    _, err := Parser("not found")
    assert.NotEqual(t, err, nil)
    assert.Equal(t, fmt.Sprintf("%s", err), "Domain is not found.")

    _, err = Parser("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS")
    assert.NotEqual(t, err, nil)
    assert.Equal(t, fmt.Sprintf("%s", err), "Domain whois data invalid.")

    dirs, err := ioutil.ReadDir("./examples/")
    assert.Equal(t, err, nil)

    for _, v := range dirs {
        domain := v.Name()
        domain_ext := domain[strings.LastIndex(domain, ".") + 1:]
        whois_raw, err := ReadFile("./examples/" + domain)
        assert.Equal(t, err, nil)

        if domain[len(domain) - 4:] == ".out" {
            continue
        }

        whois_info, err := Parser(whois_raw)
        assert.Equal(t, err, nil)

        if domain == "mjj.com" {
            assert.NotEqual(t, whois_info.registrar.registrar_id, "")
        }
        if domain_ext != "museum" && domain_ext != "at" && domain_ext != "int" {
            assert.NotEqual(t, whois_info.registrar.registrar_name, "")
        }
        if domain_ext == "com" {
            assert.NotEqual(t, whois_info.registrar.whois_server, "")
        }
        if domain_ext == "com" {
            assert.NotEqual(t, whois_info.registrar.referral_url, "")
        }
        if domain == "mjj.com" {
            assert.NotEqual(t, whois_info.registrar.domain_id, "")
        }
        assert.NotEqual(t, whois_info.registrar.domain_name, "")
        if domain_ext != "at" && domain_ext != "kr" && domain_ext != "int" {
            assert.NotEqual(t, whois_info.registrar.domain_status, "")
        }
        if domain_ext != "au" && domain_ext != "at" && domain_ext != "int" {
            assert.NotEqual(t, whois_info.registrar.created_date, "")
        }
        if domain_ext != "cn" && domain_ext != "ru" && domain_ext != "su" && domain_ext != "hk" {
            assert.NotEqual(t, whois_info.registrar.updated_date, "")
        }
        if domain_ext != "au" && domain_ext != "at" && domain_ext != "re" && domain_ext != "fr" && domain_ext != "int" {
            assert.NotEqual(t, whois_info.registrar.expiration_date, "")
        }
        assert.NotEqual(t, whois_info.registrar.name_servers, "")
        if domain_ext == "cn" {
            assert.NotEqual(t, whois_info.registrar.domain_dnssec, "")
        }

        content := ""
        content += fmt.Sprintf("registrar_id: %s\n", whois_info.registrar.registrar_id)
        content += fmt.Sprintf("registrar_name: %s\n", whois_info.registrar.registrar_name)
        content += fmt.Sprintf("whois_server: %s\n", whois_info.registrar.whois_server)
        content += fmt.Sprintf("referral_url: %s\n", whois_info.registrar.referral_url)
        content += fmt.Sprintf("domain_id: %s\n", whois_info.registrar.domain_id)
        content += fmt.Sprintf("domain_name: %s\n", whois_info.registrar.domain_name)
        content += fmt.Sprintf("domain_status: %s\n", whois_info.registrar.domain_status)
        content += fmt.Sprintf("created_date: %s\n", whois_info.registrar.created_date)
        content += fmt.Sprintf("updated_date: %s\n", whois_info.registrar.updated_date)
        content += fmt.Sprintf("expiration_date: %s\n", whois_info.registrar.expiration_date)
        content += fmt.Sprintf("name_servers: %s\n", whois_info.registrar.name_servers)
        content += fmt.Sprintf("domain_dnssec: %s\n", whois_info.registrar.domain_dnssec)

        content += fmt.Sprintf("\nregistrant\n")
        content += fmt.Sprintf("id: %s\n", whois_info.registrant.id)
        content += fmt.Sprintf("name: %s\n", whois_info.registrant.name)
        content += fmt.Sprintf("organization: %s\n", whois_info.registrant.organization)
        content += fmt.Sprintf("street: %s\n", whois_info.registrant.street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.registrant.street_ext)
        content += fmt.Sprintf("city: %s\n", whois_info.registrant.city)
        content += fmt.Sprintf("province: %s\n", whois_info.registrant.province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.registrant.postal_code)
        content += fmt.Sprintf("country: %s\n", whois_info.registrant.country)
        content += fmt.Sprintf("phone: %s\n", whois_info.registrant.phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.registrant.phone_ext)
        content += fmt.Sprintf("fax: %s\n", whois_info.registrant.fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.registrant.fax_ext)
        content += fmt.Sprintf("email: %s\n", whois_info.registrant.email)

        content += fmt.Sprintf("\nadmin\n")
        content += fmt.Sprintf("id: %s\n", whois_info.admin.id)
        content += fmt.Sprintf("name: %s\n", whois_info.admin.name)
        content += fmt.Sprintf("organization: %s\n", whois_info.admin.organization)
        content += fmt.Sprintf("street: %s\n", whois_info.admin.street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.admin.street_ext)
        content += fmt.Sprintf("city: %s\n", whois_info.admin.city)
        content += fmt.Sprintf("province: %s\n", whois_info.admin.province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.admin.postal_code)
        content += fmt.Sprintf("country: %s\n", whois_info.admin.country)
        content += fmt.Sprintf("phone: %s\n", whois_info.admin.phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.admin.phone_ext)
        content += fmt.Sprintf("fax: %s\n", whois_info.admin.fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.admin.fax_ext)
        content += fmt.Sprintf("email: %s\n", whois_info.admin.email)

        content += fmt.Sprintf("\ntech\n")
        content += fmt.Sprintf("id: %s\n", whois_info.tech.id)
        content += fmt.Sprintf("name: %s\n", whois_info.tech.name)
        content += fmt.Sprintf("organization: %s\n", whois_info.tech.organization)
        content += fmt.Sprintf("street: %s\n", whois_info.tech.street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.tech.street_ext)
        content += fmt.Sprintf("city: %s\n", whois_info.tech.city)
        content += fmt.Sprintf("province: %s\n", whois_info.tech.province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.tech.postal_code)
        content += fmt.Sprintf("country: %s\n", whois_info.tech.country)
        content += fmt.Sprintf("phone: %s\n", whois_info.tech.phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.tech.phone_ext)
        content += fmt.Sprintf("fax: %s\n", whois_info.tech.fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.tech.fax_ext)
        content += fmt.Sprintf("email: %s\n", whois_info.tech.email)

        content += fmt.Sprintf("\nbill\n")
        content += fmt.Sprintf("id: %s\n", whois_info.bill.id)
        content += fmt.Sprintf("name: %s\n", whois_info.bill.name)
        content += fmt.Sprintf("organization: %s\n", whois_info.bill.organization)
        content += fmt.Sprintf("street: %s\n", whois_info.bill.street)
        content += fmt.Sprintf("street_ext: %s\n", whois_info.bill.street_ext)
        content += fmt.Sprintf("city: %s\n", whois_info.bill.city)
        content += fmt.Sprintf("province: %s\n", whois_info.bill.province)
        content += fmt.Sprintf("postal_code: %s\n", whois_info.bill.postal_code)
        content += fmt.Sprintf("country: %s\n", whois_info.bill.country)
        content += fmt.Sprintf("phone: %s\n", whois_info.bill.phone)
        content += fmt.Sprintf("phone_ext: %s\n", whois_info.bill.phone_ext)
        content += fmt.Sprintf("fax: %s\n", whois_info.bill.fax)
        content += fmt.Sprintf("fax_ext: %s\n", whois_info.bill.fax_ext)
        content += fmt.Sprintf("email: %s\n", whois_info.bill.email)

        WriteFile("./examples/" + v.Name() + ".out", content)
    }
}
