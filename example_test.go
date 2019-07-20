package ldap_test

import (
	"log"

	"github.com/jtblin/go-ldap-client"
)

// ExampleLDAPClient_Authenticate shows how a typical application can verify a login attempt
func ExampleLDAPClient_Authenticate() {
	client := &ldap.LDAPClient{
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

	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)

}

// ExampleLDAPClient_GetGroupsOfUser shows how to retrieve user groups
func ExampleLDAPClient_GetGroupsOfUser() {
	client := &ldap.LDAPClient{
		Base:        "dc=example,dc=com",
		Host:        "ldap.example.com",
		Port:        389,
		GroupFilter: "(memberUid=%s)",
	}
	defer client.Close()
	groups, err := client.GetGroupsOfUser("username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups)
}

// ExampleLDAPClient_AuthenticateGroups shows how to check if user is in the allowed groups
func ExampleLDAPClient_AuthenticateGroups() {
	client := &ldap.LDAPClient{
		Base:         		 "dc=example,dc=com",
		Host:         		 "ldap.example.com",
		Port:         		 389,
		UseSSL:       		 false,
		BindDN:       		 "uid=readonlyuser,ou=People,dc=example,dc=com",
		BindPassword: 		 "readonlypassword",
		UserFilter:   		 "(sAMAccountName=%s)",
		GroupsAllowed: 		 []string{"Testgroup", "Webgroup", "Admingroup"},
		GroupsAllowedFilter: "(&(sAMAccountName=%s)(memberOf=CN=%s,dc=example,dc=com))",
		Attributes:   		 []string{"cn", "givenName", "sn", "mail", "uid"},
	}

	defer client.Close()
	
	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)
	
	groups, err := client.AuthenticateGroups("username")
	if err != nil {
	log.Printf("Error getting groups for user %s: %+v", "username", err)
	} else if groups == false {
	log.Printf("Authentication failed: User %s is not in the allowed groups.", "username")
	} else {
	log.Printf("Authentication successful: User %s is logged in.", "username")
	}
}
