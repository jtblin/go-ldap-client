# go-ldap-client

[![Go Reference](https://pkg.go.dev/badge/github.com/jtblin/go-ldap-client/v2.svg)](https://pkg.go.dev/github.com/jtblin/go-ldap-client/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/jtblin/go-ldap-client/v2)](https://goreportcard.com/report/github.com/jtblin/go-ldap-client/v2)
[![CI](https://github.com/jtblin/go-ldap-client/actions/workflows/ci.yml/badge.svg)](https://github.com/jtblin/go-ldap-client/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jtblin/go-ldap-client/branch/main/graph/badge.svg)](https://codecov.io/gh/jtblin/go-ldap-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/jtblin/go-ldap-client)](https://github.com/jtblin/go-ldap-client/releases)

Simple LDAP client for Go to authenticate users, retrieve basic information, and fetch groups.

## Features

- **Modern Go**: Supports Go modules and `context.Context`.
- **Security**: Fixes unauthenticated bind (anonymous bind) vulnerabilities with empty passwords.
- **Resiliency**: Supports multiple LDAP hosts with automatic failover.
- **Flexibility**: Support for multi-valued attributes (e.g., `memberOf`).
- **Customization**: Easily provide custom TLS configurations, Root CAs, or client certificates.
- **Testable**: Extracting an interface for the LDAP connection for easy mocking in your applications.

## Installation

```bash
go get github.com/jtblin/go-ldap-client/v2
```

## Usage

### Simple Authentication

```go
package main

import (
	"log"

	"github.com/jtblin/go-ldap-client/v2"
)

func main() {
	client := &ldap.Client{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		UseSSL:       false,
		BindDN:       "uid=readonlyuser,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ctx := context.Background()
	ok, user, err := client.Authenticate(ctx, "username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	// User struct contains DN and Attributes
	log.Printf("User DN: %s", user.DN)
	log.Printf("User Attributes: %+v", user.Attributes)
	
	groups, err := client.GetGroupsOfUser(ctx, "username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups) 
}
```

### Context Support & Multiple Hosts

All methods in v2.0.0+ require a `context.Context` as the first argument.

```go
client := &ldap.Client{
    Base:               "dc=example,dc=com",
    Hosts:              []string{"ldap1.example.com", "ldap2.example.com"},
    Port:               636,
    UseSSL:             true,
    InsecureSkipVerify: false,
    ServerName:         "ldap.example.com",
}

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

ok, user, err := client.Authenticate(ctx, "username", "password")
```

### Getting User Information (Search without password)

If you only need to retrieve user information or their DN without verifying a password:

```go
user, err := client.GetUser(ctx, "username")
if err != nil {
    log.Fatal(err)
}
log.Printf("Found DN: %s", user.DN)
```

### Custom TLS Configuration

```go
tlsConfig := &tls.Config{
    RootCAs: myRootCAs,
}
client := &ldap.Client{
    // ...
    TLSConfig: tlsConfig,
}
```

### Active Directory Configuration

For Active Directory, you typically need to use the user's `sAMAccountName` for searching and the full `DN` for group membership checks:

```go
client := &ldap.Client{
    Base:         "dc=example,dc=org",
    Host:         "ad.example.org",
    Port:         389,
    BindDN:       "cn=readonly,ou=ServiceAccounts,dc=example,dc=org",
    BindPassword: "password",
    UserFilter:   "(sAMAccountName=%s)",
    // In v2.1.0+, you can use {dn} or {username} tokens in the GroupFilter.
    // For AD, you typically need the user's full DN.
    GroupFilter:  "(member={dn})", 
    Attributes:   []string{"sAMAccountName", "mail", "cn"},
}
```

## Documentation

Full documentation can be found on [pkg.go.dev](https://pkg.go.dev/github.com/jtblin/go-ldap-client/v2).

## License

MIT