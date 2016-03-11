# whois-parser.go

whois-parser-go is a simple Go module for whois info parser.

[![Build Status](https://secure.travis-ci.org/likexian/whois-parser-go.png)](https://secure.travis-ci.org/likexian/whois-parser-go)

## Overview

It will parse the provided whois information and return a readable data struct.

*Work for most domain extensions and most of the time.*

## Installation

    go get github.com/likexian/whois-parser-go

## Importing

    import (
        "github.com/likexian/whois-parser-go"
    )

## Documentation

    func Parser(whois string) (whois_info WhoisInfo, err error)

## Example

    result, err := whois_parser.Parser(whois_raw)
    if err == nil {
        // Print the domain status
        fmt.Println(result.Registrar.DomainStatus)

        // Print the domain created date
        fmt.Println(result.Registrar.CreatedDate)

        // Print the domain expiration date
        fmt.Println(result.Registrar.ExpirationDate)

        // Print the registrant name
        fmt.Println(result.Registrant.Name)

        // Print the registrant email address
        fmt.Println(result.Registrant.Email)
    }

## LICENSE

Copyright 2014, Kexian Li

Apache License, Version 2.0

## Whois info query in Go

Please refer to [whois-go](https://github.com/likexian/whois-go)

## About

- [Kexian Li](http://github.com/likexian)
- [http://www.likexian.com/](http://www.likexian.com/)
