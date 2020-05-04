# WhoisParser

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/likexian/whois-parser-go?status.svg)](https://godoc.org/github.com/likexian/whois-parser-go)
[![Build Status](https://travis-ci.org/likexian/whois-parser-go.svg?branch=master)](https://travis-ci.org/likexian/whois-parser-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/likexian/whois-parser-go)](https://goreportcard.com/report/github.com/likexian/whois-parser-go)
[![Code Cover](https://codecov.io/gh/likexian/whois-parser-go/graph/badge.svg)](https://codecov.io/gh/likexian/whois-parser-go)

WhoisParser is s simple Go module for domain whois information parsing.

## Overview

This module parses the provided whois information and returns a readable data struct.

## Verified Extensions

It is supposed to be working with all domain extensions, but [verified extensions](examples/README.md) must works, because I have checked them one by one manually.

If there is any problems, please feel free to open a new issue.

## Binary distributions

For binary distributions of whois information query and parsing, please download [whois release tool](https://github.com/likexian/whois-go/tree/master/cmd/whois).

## Installation

```shell
go get github.com/likexian/whois-parser-go
```

## Importing

```go
import (
    "github.com/likexian/whois-parser-go"
)
```

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

## Whois information query

Please refer to [whois-go](https://github.com/likexian/whois-go)

## License

Copyright 2014-2020 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).
