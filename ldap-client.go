// Package ldap provides a simple LDAP client to authenticate users,
// retrieve basic information and groups.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// User represents an LDAP user entry.
type User struct {
	// DN is the Distinguished Name of the user.
	DN string
	// Attributes is a map of attributes retrieved for the user.
	Attributes map[string][]string
}

// Conn is an interface for the LDAP connection to allow mocking.
type Conn interface {
	Bind(username, password string) error
	Close() error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(config *tls.Config) error
	SetTimeout(time.Duration)
}

// Client represents the configuration for the LDAP client.
type Client struct {
	// Attributes is a list of attributes to retrieve for the user.
	Attributes []string
	// Base is the base DN to search for users.
	Base string
	// BindDN is the DN of the user to use for the initial search.
	BindDN string
	// BindPassword is the password of the BindDN user.
	BindPassword string
	// GroupFilter is the LDAP filter to use for retrieving groups (e.g. "(memberUid=%s)").
	GroupFilter string
	// Host is the LDAP host to connect to (legacy single host).
	Host string
	// Hosts is a list of LDAP hosts to connect to for failover support.
	Hosts []string
	// ServerName is the server name to use for TLS verification.
	ServerName string
	// UserFilter is the LDAP filter to use for searching for users (e.g. "(uid=%s)").
	UserFilter string
	// Conn is the underlying LDAP connection.
	Conn Conn
	// Port is the LDAP port to connect to.
	Port int
	// InsecureSkipVerify allows skipping TLS verification (not recommended for production).
	InsecureSkipVerify bool
	// UseSSL enables LDAPS connection.
	UseSSL bool
	// SkipTLS disables StartTLS when using non-SSL connection.
	SkipTLS bool
	// ClientCertificates provides client-side certificates for MTLS.
	ClientCertificates []tls.Certificate
	// TLSConfig provides a custom TLS configuration. If set, it overrides other TLS settings.
	TLSConfig *tls.Config
}

// Connect connects to the ldap backend.
func (lc *Client) Connect(ctx context.Context) error {
	if lc.Conn != nil {
		return nil
	}

	hosts := lc.Hosts
	if len(hosts) == 0 {
		hosts = []string{lc.Host}
	}

	var lastErr error
	for _, host := range hosts {
		address := fmt.Sprintf("%s:%d", host, lc.Port)
		l, err := lc.dial(ctx, address)
		if err != nil {
			lastErr = err
			continue
		}
		lc.Conn = l
		return nil
	}

	return fmt.Errorf("failed to connect to any ldap host: %w", lastErr)
}

func (lc *Client) dial(ctx context.Context, address string) (Conn, error) {
	var l *ldap.Conn
	var err error

	tlsConfig := lc.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: lc.InsecureSkipVerify, //nolint:gosec // This is a user-configurable option for testing/development environments.
			ServerName:         lc.ServerName,
			Certificates:       lc.ClientCertificates,
		}
	}

	if !lc.UseSSL {
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s", address))
		if err != nil {
			return nil, err
		}

		if !lc.SkipTLS {
			err = l.StartTLS(tlsConfig)
			if err != nil {
				l.Close()
				return nil, err
			}
		}
	} else {
		l, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", address), ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, err
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		l.SetTimeout(time.Until(deadline))
	}

	return l, nil
}

// Close closes the ldap backend connection.
func (lc *Client) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// GetUser searches for the given username and returns their attributes and DN.
func (lc *Client) GetUser(ctx context.Context, username string) (*User, error) {
	err := lc.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	attributes := make([]string, 0, len(lc.Attributes)+1)
	attributes = append(attributes, lc.Attributes...)
	attributes = append(attributes, "dn")

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
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("user does not exist")
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("too many entries returned")
	}

	user := &User{
		DN:         sr.Entries[0].DN,
		Attributes: map[string][]string{},
	}

	for _, attr := range lc.Attributes {
		user.Attributes[attr] = sr.Entries[0].GetAttributeValues(attr)
	}

	return user, nil
}

// Authenticate authenticates the user against the ldap backend.
func (lc *Client) Authenticate(ctx context.Context, username, password string) (bool, *User, error) {
	if password == "" {
		return false, nil, errors.New("authentication failed: empty password")
	}

	user, err := lc.GetUser(ctx, username)
	if err != nil {
		return false, nil, err
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(user.DN, password)
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

// GetGroupsOfUser returns the group for a user.
func (lc *Client) GetGroupsOfUser(ctx context.Context, username string) ([]string, error) {
	err := lc.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"},
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
