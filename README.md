# WhoisParser

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/likexian/whois-parser?status.svg)](https://godoc.org/github.com/likexian/whois-parser)
[![Build Status](https://travis-ci.org/likexian/whois-parser.svg?branch=master)](https://travis-ci.org/likexian/whois-parser)
[![Go Report Card](https://goreportcard.com/badge/github.com/likexian/whois-parser)](https://goreportcard.com/report/github.com/likexian/whois-parser)
[![Code Cover](https://codecov.io/gh/likexian/whois-parser/graph/badge.svg)](https://codecov.io/gh/likexian/whois-parser)

WhoisParser is a simple Go module for domain whois information parsing.

## Overview

This module parses the provided domain whois information and returns a readable data struct.

## Verified Extensions

It is supposed to be working with all domain extensions, but [verified extensions](examples/README.md) must works, because I have checked them one by one manually.

If there is any problem, please feel free to open a new issue.

## Binary distributions

For binary distributions of whois information query and parsing, please download [whois release tool](https://github.com/likexian/whois/tree/master/cmd/whois).

## Installation

```shell
go get github.com/likexian/whois-parser
```

## Importing

```go
import (
    "github.com/likexian/whois-parser"
)
```

## Documentation

Visit the docs on [GoDoc](https://godoc.org/github.com/likexian/whois-parser)

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

Please refer to [whois](https://github.com/likexian/whois)

## License

Copyright 2014-2021 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).
