package ldap_test

import (
	"context"
	"log"
	"time"

	"github.com/jtblin/go-ldap-client/v2"
)

// ExampleClient_Authenticate shows how a typical application can verify a login attempt
func ExampleClient_Authenticate() {
	client := &ldap.Client{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		UseSSL:       false,
		BindDN:       "uid=readonlysuer,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	defer client.Close()

	ok, user, err := client.Authenticate(context.Background(), "username", "password")
	if err != nil {
		log.Printf("Error authenticating user %s: %+v", "username", err)
		return
	}
	if !ok {
		log.Printf("Authenticating failed for user %s", "username")
		return
	}
	log.Printf("User: %+v", user)
}

// ExampleClient_Authenticate_timeout shows how to use the context-aware Authenticate method with a timeout
func ExampleClient_Authenticate_timeout() {
	client := &ldap.Client{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		UseSSL:       false,
		BindDN:       "uid=readonlysuer,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, user, err := client.Authenticate(ctx, "username", "password")
	if err != nil {
		log.Printf("Error authenticating user %s: %+v", "username", err)
		return
	}
	if !ok {
		log.Printf("Authenticating failed for user %s", "username")
		return
	}
	log.Printf("User: %+v", user)
}

// ExampleClient_GetGroupsOfUser shows how to retrieve user groups
func ExampleClient_GetGroupsOfUser() {
	client := &ldap.Client{
		Base:        "dc=example,dc=com",
		Host:        "ldap.example.com",
		Port:        389,
		GroupFilter: "(memberUid=%s)",
	}
	defer client.Close()
	groups, err := client.GetGroupsOfUser(context.Background(), "username")
	if err != nil {
		log.Printf("Error getting groups for user %s: %+v", "username", err)
		return
	}
	log.Printf("Groups: %+v", groups)
}
