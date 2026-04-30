package main

import (
	"flag"
	"log"
	"strings"

	"github.com/jtblin/go-ldap-client"
)

var base, bindDN, bindPassword, groupFilter, host, password, serverName, userFilter, username string
var hosts string
var port int
var useSSL bool
var skipTLS bool

func main() {
	flag.Parse()

	client := &ldap.Client{
		Base:         base,
		Host:         host,
		Hosts:        strings.Split(hosts, ","),
		Port:         port,
		UseSSL:       useSSL,
		SkipTLS:      skipTLS,
		BindDN:       bindDN,
		BindPassword: bindPassword,
		UserFilter:   userFilter,
		GroupFilter:  groupFilter,
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
		ServerName:   serverName,
	}
	defer client.Close()

	ok, user, err := client.Authenticate(username, password)
	if err != nil {
		log.Printf("Error authenticating user %s: %+v", username, err)
		return
	}
	if !ok {
		log.Printf("Authenticating failed for user %s", username)
		return
	}
	log.Printf("User: %+v", user)

	groups, err := client.GetGroupsOfUser(username)
	if err != nil {
		log.Printf("Error getting groups for user %s: %+v", username, err)
		return
	}
	log.Printf("Groups: %+v", groups)
}

const defaultLDAPPort = 389

func init() {
	flag.StringVar(&base, "base", "dc=example,dc=com", "Base LDAP")
	flag.StringVar(&bindDN, "bind-dn", "uid=readonlysuer,ou=People,dc=example,dc=com", "Bind DN")
	flag.StringVar(&bindPassword, "bind-pwd", "readonlypassword", "Bind password")
	flag.StringVar(&groupFilter, "group-filter", "(memberUid=%s)", "Group filter")
	flag.StringVar(&host, "host", "ldap.example.com", "LDAP host")
	flag.StringVar(&hosts, "hosts", "", "Comma separated list of LDAP hosts")
	flag.StringVar(&password, "password", "", "Password")
	flag.IntVar(&port, "port", defaultLDAPPort, "LDAP port")
	flag.StringVar(&userFilter, "user-filter", "(uid=%s)", "User filter")
	flag.StringVar(&username, "username", "", "Username")
	flag.StringVar(&serverName, "server-name", "", "Server name for SSL (if use-ssl is set)")
	flag.BoolVar(&useSSL, "use-ssl", false, "Use SSL")
	flag.BoolVar(&skipTLS, "skip-tls", false, "Skip TLS start")
}
