# go-ldap-client

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
go get github.com/jtblin/go-ldap-client
```

## Usage

### Simple Authentication

```go
package main

import (
	"log"

	"github.com/jtblin/go-ldap-client"
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

	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)
	
	groups, err := client.GetGroupsOfUser("username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups) 
}
```

### Context Support & Multiple Hosts

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

ok, user, err := client.AuthenticateContext(ctx, "username", "password")
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

## Documentation

Full documentation can be found on [pkg.go.dev](https://pkg.go.dev/github.com/jtblin/go-ldap-client).

## License

MIT