// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"fmt"
	"errors"
	"golang.org/x/text/encoding/unicode"
	"gopkg.in/ldap.v2"
)

const (
	// adPasswordAttribute is the password attribute name in active directory.
	adPasswordAttributeName = "UnicodePwd"
	// openLdapPasswordAttributeName is the password attribute name in open ldap.
	openLdapPasswordAttributeName = "userPassword"
)

var (
	// errUserNotExist represents a situation in which the user object doesn't exist.
	errUserNotExist = fmt.Errorf("user does not exist")
	// errUserNotIdentified represents a situation in which the user could not be identified.
	errUserNotIdentified = fmt.Errorf("user could not be indentifed")
)
type LDAPClienter interface {
	Connect() error
	Bind(dn,password string) error
	Close()
	UsersSearch(orFilter string,uidAttr string) (bool, map[string]map[string][]string, error)
	RunQueries(username string, queries []string) (results map[string]bool, err error)
	GetAllGroupsByName(groupName string) ([]*LdapGroup, error)
	GetAllGroupsWithMembersByDN(groupDN []string) ([]*LdapGroup, error)
	ChangeADUserPassword(username, oldPassword, newPassword string) (err error)
    ChangeOpenLDAPUserPassword(username, oldPassword, newPassword string) (err error)
	GetUserByCN(userCN ,uidAttr string)(uid string, err error)
	Authenticate(username string, password string) (bool, map[string][]string, error)
}
type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
	GroupsDN           string
}

type LdapGroup struct {
	Name              string
	DistinguishedName string
	Members			  []string
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

func (lc *LDAPClient) Bind(dn,password string) error {
	if err := lc.Conn.Bind(dn,password); err != nil {
		return fmt.Errorf("LDAP: cannot bind to server: invalid credentials or bad DN %v",err)
	}
	return nil
}
// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string][]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errUserNotExist
	}

	if len(sr.Entries) > 1 {
		return false, nil, errUserNotIdentified
	}

	userDN := sr.Entries[0].DN
	user := map[string][]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValues(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}

// UsersSearch Retrieves users from the provided list and returns them with attributes.
func (lc *LDAPClient) UsersSearch(orFilter string,uidAttr string) (bool, map[string]map[string][]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes,uidAttr)
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		orFilter,
		attributes,
		nil,
	)

	searchResult, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(searchResult.Entries) < 1 {
		return false, nil, errUserNotExist
	}

	users:=map[string]map[string][]string{}
	for _, entry := range searchResult.Entries {
		user := map[string][]string{}
		for _, attr := range attributes {
			val := entry.GetAttributeValues(attr)
			if len(val) > 0{
				user[attr] = val
			}
		}
		users[entry.GetAttributeValue(uidAttr)] = user
	}
	return true, users, nil
}
// RunQueries runs the given ldap queries against the ldap backend and returns the matched queries.
func (lc *LDAPClient) RunQueries(username string, queries []string) (results map[string]bool, err error) {
	if err = lc.Connect(); err != nil {
		return
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		if err = lc.Conn.Bind(lc.BindDN, lc.BindPassword); err != nil {
			return
		}
	}

	results = map[string]bool{}

	attributes := []string{"dn"}
	userFilter := fmt.Sprintf(lc.UserFilter, username)

	for _, query := range queries {
		searchRequest := ldap.NewSearchRequest(
			lc.Base,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&%s%s)", userFilter, query),
			attributes,
			nil,
		)

		var sr *ldap.SearchResult
		if sr, err = lc.Conn.Search(searchRequest); err != nil {
			return
		}

		if len(sr.Entries) == 1 {
			results[query] = true
		}
	}

	return
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// GetAllGroupsByName returns list of groups matching a name.
func (lc *LDAPClient) GetAllGroupsByName(groupName string) ([]*LdapGroup, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		if err = lc.Conn.Bind(lc.BindDN, lc.BindPassword); err != nil {
			return nil, nil
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=Group)(cn=*%s*))", groupName),
		[]string{"cn"},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	var groups []*LdapGroup
	for _, entry := range sr.Entries {
		group := &LdapGroup{
			Name:              entry.GetAttributeValue("cn"),
			DistinguishedName: entry.DN,
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// GetAllGroupsWithMembersByDN returns a list of groups with selected config matching a name. members are included in result
func (lc *LDAPClient) GetAllGroupsWithMembersByDN(groupDN []string) ([]*LdapGroup, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	// First bind with a read only user
	if err = lc.Conn.Bind(lc.BindDN, lc.BindPassword); err != nil {
		return nil, err
	}
    var (
		searchRequest *ldap.SearchRequest
		searchResult *ldap.SearchResult
    )
	groups:= make([]*LdapGroup,0)
	if len(groupDN) == 0 {
		searchRequest = ldap.NewSearchRequest(
			lc.GroupsDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=Group))",
			[]string{"cn", "member", "memberUid"},
			nil,
		)

		searchResult, err = lc.Conn.Search(searchRequest)
		if err != nil {
			return nil, err
		}
		for _, entry := range searchResult.Entries {
			group := LdapGroup{
				Name:              entry.GetAttributeValue("cn"),
				DistinguishedName: entry.DN,
				Members:           entry.GetAttributeValues("member"),
			}

			groups = append(groups, &group)
		}
		return groups, nil
	}else{
		for _, groupDN := range groupDN {
			searchRequest = ldap.NewSearchRequest(
				groupDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(&(objectClass=Group))",
				[]string{"cn", "member", "memberUid"},
				nil,
			)

			searchResult, err = lc.Conn.Search(searchRequest)
			if err != nil {
				return nil, err
			}
			for _, entry := range searchResult.Entries {
				group := LdapGroup{
					Name:              entry.GetAttributeValue("cn"),
					DistinguishedName: entry.DN,
					Members:           entry.GetAttributeValues("member"),
				}

				groups = append(groups, &group)
			}
		}
		return groups, nil
	}
}

// ChangeADUserPassword changes user's password in Active Directory
func (lc *LDAPClient) ChangeADUserPassword(username, oldPassword, newPassword string) (err error) {
	if err = lc.Connect(); err != nil {
		return NewLDAPError("couldn't connect to ldap server", err)
	}
	var userDN string
	if userDN, err = lc.getUserDN(username); err != nil {
		return NewLDAPError("failed to retrieve user dn", err)
	}

	// bind as the user to verify their current password
	if err = lc.Conn.Bind(userDN, oldPassword); err != nil {
		return NewLDAPError("could not bind user via old password", err)
	}

	var oldEncodedPass, newEncodedPass string

	if oldEncodedPass, err = lc.encodePasswordForAD(oldPassword); err != nil {
		return NewLDAPError("failed to encode old password to ad format", err)
	}
	if newEncodedPass, err = lc.encodePasswordForAD(newPassword); err != nil {
		return NewLDAPError("failed to encode new password to ad format", err)
	}

	modify := ldap.NewModifyRequest(userDN)
	modify.Delete(adPasswordAttributeName, []string{oldEncodedPass})
	modify.Add(adPasswordAttributeName, []string{newEncodedPass})
	if err = lc.Conn.Modify(modify); err != nil {
		return NewLDAPError("password could not be changed", err)
	}

	// bind as the user to verify their new password
	if err = lc.Conn.Bind(userDN, newPassword); err != nil {
		return NewLDAPError("could not bind user via new password", err)
	}

	return nil
}

// ChangeOpenLDAPUserPassword changes user's password.
func (lc *LDAPClient) ChangeOpenLDAPUserPassword(username, oldPassword, newPassword string) (err error) {
	if err = lc.Connect(); err != nil {
		return NewLDAPError("couldn't connect to ldap server", err)
	}
	var userDN string
	if userDN, err = lc.getUserDN(username); err != nil {
		return NewLDAPError("failed to retrieve user dn", err)
	}

	// bind as the user to verify their current password
	if err = lc.Conn.Bind(userDN, oldPassword); err != nil {
		return NewLDAPError("could not bind user via old password", err)
	}

	modify := ldap.NewModifyRequest(userDN)
	modify.Replace(openLdapPasswordAttributeName, []string{newPassword})
	if err = lc.Conn.Modify(modify); err != nil {
		return NewLDAPError("password could not be changed", err)
	}

	// bind as the user to verify their new password
	if err = lc.Conn.Bind(userDN, newPassword); err != nil {
		return NewLDAPError("could not bind user via new password", err)
	}

	return nil
}

func (lc *LDAPClient) GetUserByCN(userCN, uidAttr string)(uid string, err error){
	searchRequest := ldap.NewSearchRequest(
		userCN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"cn", uidAttr},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}
	if len(sr.Entries) != 1 {
		return "", errors.New("found mor that one user")
	}
	userEntry := sr.Entries[0]
	uid = userEntry.GetAttributeValue(uidAttr)
	return  uid,nil
}

func (lc *LDAPClient) getUserDN(username string) (string, error) {
	var err error
	if err = lc.Connect(); err != nil {
		return "", NewLDAPError("dn retrieval failed - couldn't connect to ldap server", err)
	}

	// first bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		if err = lc.Conn.Bind(lc.BindDN, lc.BindPassword); err != nil {
			return "", NewLDAPError("dn retrieval failed - could not bind read only user", err)
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	var searchResult *ldap.SearchResult
	if searchResult, err = lc.Conn.Search(searchRequest); err != nil {
		return "", NewLDAPError("wasn't able to find user dn in ldap", err)
	}

	if len(searchResult.Entries) < 1 {
		return "", errUserNotExist
	}

	if len(searchResult.Entries) > 1 {
		return "", errUserNotIdentified
	}

	return searchResult.Entries[0].DN, nil
}

// encodePasswordForAD encodes the password for active directory.
func (lc *LDAPClient) encodePasswordForAD(pass string) (encoded string, err error) {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	if encoded, err = utf16.NewEncoder().String(fmt.Sprintf("%q", pass)); err != nil {
		err = fmt.Errorf("password could not be utf16 encoded: %w", err)
	}
	return
}
