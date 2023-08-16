package ldap

import (
	"log"
	"testing"
)
//tested with this LDAP: https://github.com/rroemhild/docker-test-openldap
func Test_LDAPClient(t *testing.T) {

	t.Run("Authenticate", func(t *testing.T) {
		client := &LDAPClient{
			Base:         "dc=planetexpress,dc=com",
			Host:         "localhost",
			Port:         10389,
			UseSSL:       false,
			BindDN:       "cn=admin,dc=planetexpress,dc=com",
			BindPassword: "GoodNewsEveryone",
			UserFilter:   "(uid=%s)",
			GroupFilter:  "(memberUid=%s)",
			Attributes:   []string{"givenName", "sn", "mail", "uid"},
		}
		defer client.Close()

		ok, user, err := client.Authenticate("professor", "professor")
		if err != nil {
			log.Fatalf("Error authenticating user %s: %+v", "professor", err)
		}
		if !ok {
			log.Fatalf("Authenticating failed for user %s", "username")
		}
		log.Printf("User: %+v", user)
	})

	t.Run("GetGroupsOfUser", func(t *testing.T) {
		client := &LDAPClient{
			Base:        "dc=planetexpress,dc=com",
			Host:        "localhost",
			Port:        10389,
			GroupFilter: "(memberUid=%s)",
			UseSSL:       false,
		}
		defer client.Close()
		groups, err := client.GetGroupsOfUser("fry")
		if err != nil {
			log.Fatalf("Error getting groups for user %s: %+v", "fry", err)
		}
		log.Printf("Groups: %+v", groups)
	})

	t.Run("GetAllGroupsWithMembersByName-Get all external groups for ldap with their members", func(t *testing.T) {
		client := &LDAPClient{
			Base:        "dc=planetexpress,dc=com",
			Host:        "localhost",
			Port:        10389,
			UseSSL:       false,
			GroupFilter: "(memberUid=%s)",
			InsecureSkipVerify:false,
		}
		defer client.Close()
		groups, err := client.GetAllGroupsWithMembersByName([]string{""})
		if err != nil {
			log.Fatalf("Error getting all groups%+v", err)
		}
		log.Printf("Groups: %+v", groups)
	})

	t.Run("RunQueries", func(t *testing.T) {
		client := &LDAPClient{
			Base:        "dc=planetexpress,dc=com",
			Host:        "localhost",
			Port:        10389,
			UseSSL:       false,
			BindDN:       "cn=admin,dc=planetexpress,dc=com",
			BindPassword: "GoodNewsEveryone",
			UserFilter:   "(uid=%s)",
			GroupFilter:  "(memberUid=%s)",
			Attributes:   []string{"givenName", "sn", "mail", "uid"},
			InsecureSkipVerify:false,
		}
		defer client.Close()

		ok, user, err := client.Authenticate("fry", "fry")
		if err != nil {
			log.Fatalf("Error authenticating user %s: %+v", "username", err)
		}
		if !ok {
			log.Fatalf("Authenticating failed for user %s", "username")
		}
		log.Printf("User: %+v", user)

		query := "(ou=Office Management)"
		attribute := "cn"
		results, err := client.RunQueries("fry", []string{"(ou=Delivering Crew)", "(ou=Ship Crew)"})
		if err != nil {
			log.Fatalf("Error searching query %s and attribute %s: %+v", query, attribute, err)
		}

		log.Printf("found: %+v", results)
	})

	t.Run("GetAllGroupsByName", func(t *testing.T) {
		client := &LDAPClient{
			Base:        "dc=planetexpress,dc=com",
			Host:        "localhost",
			Port:        10389,
			UseSSL:       false,
			BindDN:       "cn=admin,dc=planetexpress,dc=com",
			BindPassword: "GoodNewsEveryone",
			UserFilter:   "(uid=%s)",
			GroupFilter:  "(memberUid=%s)",
			Attributes:   []string{"cn", "member", "memberUid"},
		}
		defer client.Close()

		results, err := client.GetAllGroupsByName("_")
		if err != nil {
			log.Fatalf("Error getting all groups  matching to %s, %v", "ship_crew", err)
		}

		log.Printf("found: %+v", results)
	})

	t.Run("ChangeUserPassword", func(t *testing.T) {
		client := &LDAPClient{
			Base:               "DC=trial,DC=local",
			Host:               "34.244.56.18",
			Port:               636,
			UseSSL:             true,
			SkipTLS:            false,
			InsecureSkipVerify: true,
			BindDN:             "CN=mike-t,DC=trial,DC=local",
			BindPassword:       "Aa123456#",
			UserFilter:         "(sAMAccountName=%s)",
			GroupFilter:        "(gid=%s)",
			Attributes:         []string{"sAMAccountName", "uid"},
		}
		defer client.Close()

		oldPassword, newPassword := "Aa123456#", "Vv123456#"
		err := client.ChangeADUserPassword("mike-t", oldPassword, newPassword)
		if err != nil {
			log.Fatalf("Error changing user password from %s to %s, %v", oldPassword, newPassword, err)
		}
	})
}
