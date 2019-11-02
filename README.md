# whois-parser.go

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/likexian/whois-parser-go?status.svg)](https://godoc.org/github.com/likexian/whois-parser-go)
[![Build Status](https://travis-ci.org/likexian/whois-parser-go.svg?branch=master)](https://travis-ci.org/likexian/whois-parser-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/likexian/whois-parser-go)](https://goreportcard.com/report/github.com/likexian/whois-parser-go)
[![Code Cover](https://codecov.io/gh/likexian/whois-parser-go/graph/badge.svg)](https://codecov.io/gh/likexian/whois-parser-go)

whois-parser-go is a simple Go module for domain whois info parse.

## Overview

This module parses the provided whois information and return a readable data struct.

## Verified Extensions

It is supposed to be working with all domain extensions, but [verified extensions](examples/README.md) must works, because I have checked them one by one manually.

If there is any problems, please feel free to open a new issue.

## Installation

    go get github.com/likexian/whois-parser-go

## Importing

    import (
        "github.com/likexian/whois-parser-go"
    )

## Documentation

Visit the docs on [GoDoc](https://godoc.org/github.com/likexian/whois-parser-go)

## Example

```go
result, err := whoisparser.Parse(whois_raw)
if err == nil {
    // Print the domain status
    fmt.Println(result.Domain.Status)

    // Print the domain created date
    fmt.Println(result.Domain.CreatedDate)

    // Print the domain expiration date
    fmt.Println(result.Domain.ExpirationDate)

    // Print the registrar name
    fmt.Println(result.Registrar.Name)

    // Print the registrant name
    fmt.Println(result.Registrant.Name)

    // Print the registrant email address
    fmt.Println(result.Registrant.Email)
}
```

## Whois info query in Go

Please refer to [whois-go](https://github.com/likexian/whois-go)

## LICENSE

Copyright 2014-2019 Li Kexian

Licensed under the Apache License 2.0

## About

- [Li Kexian](https://www.likexian.com/)

## DONATE

- [Help me make perfect](https://www.likexian.com/donate/)
