# whois-parser.go

whois-parser-go is a simple Go module for whois info parser.

[![Build Status](https://secure.travis-ci.org/likexian/whois-parser-go.png)](https://secure.travis-ci.org/likexian/whois-parser-go)

## Overview

It will parser the provided whois information and reutrn a readable data in struct.

Work for most domain extensions and most of the time.

## Installation

    go get github.com/likexian/whois-parser-go

## Importing

    import (
        "github.com/likexian/whois-parser-go"
    )

## Documentation

The parser function

    func Parser(whois string) (whois_info WhoisInfo, err error)

The return data struct

    type WhoisInfo struct {
        registrar Registrar
        registrant Registrant
        admin Registrant
        tech Registrant
        bill Registrant
    }

The registrar struct in whois_info

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

The registrant/admin/tech/bill struct in whois_info

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

## Example

    result, err := whois_parser.Parser(string whois_raw)
    if err != nil {
        // Print the domain status
        fmt.Println(result.registrar.domain_status)

        // Print the domain created date
        fmt.Println(result.registrar.created_date)

        // Print the domain expiration date
        fmt.Println(result.registrar.expiration_date)

        // Print the registrant name
        fmt.Println(result.registrant.name)

        // Print the registrant email address
        fmt.Println(result.registrant.email)
    }

## LICENSE

Copyright 2014, Kexian Li

Apache License, Version 2.0

## Whois info query in Go

Please refer to [whois-go](https://github.com/likexian/whois-go)

## About

- [Kexian Li](http://github.com/likexian)
- [http://www.likexian.com/](http://www.likexian.com/)
