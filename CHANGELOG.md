# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.25.0] - 2024-05-30

### Added
- IP WHOIS parsing capability
- New `IPInfo` struct to store IP WHOIS information
- Updated `Parse` function to handle both domain and IP WHOIS
- New `parseIPWhois` function to parse IP WHOIS information
- New `isIPWhois` function to detect IP WHOIS input
- Added IP WHOIS parsing example in README.md
- New test cases for IP WHOIS parsing in ip_parser_test.go

### Changed
- Updated error handling to support IP WHOIS errors
- Modified project description to include IP WHOIS parsing
- Updated Version function to reflect the new feature (1.25.0)

## [1.24.22] - 2024-05-29

- Previous version (changes not documented)