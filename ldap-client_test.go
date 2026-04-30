package ldap

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type mockConn struct {
	bindErr      error
	searchResult *ldap.SearchResult
	searchErr    error
	startTLSErr  error
	closed       bool
	boundDN      string
	boundPWD     string
}

func (m *mockConn) Bind(username, password string) error {
	m.boundDN = username
	m.boundPWD = password
	return m.bindErr
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return m.searchResult, m.searchErr
}

func (m *mockConn) StartTLS(_ *tls.Config) error {
	return m.startTLSErr
}

func (m *mockConn) SetTimeout(_ time.Duration) {}

func TestAuthenticate_EmptyPassword(t *testing.T) {
	client := &Client{}
	ok, _, err := client.Authenticate("user", "")
	if ok {
		t.Error("expected authentication to fail for empty password")
	}
	if err == nil || err.Error() != "authentication failed: empty password" {
		t.Errorf("expected empty password error, got %v", err)
	}
}

func TestAuthenticate_Success(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "uid=testuser,dc=example,dc=com",
					Attributes: []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"testuser"}},
						{Name: "mail", Values: []string{"test@example.com"}},
					},
				},
			},
		},
	}

	client := &Client{
		Conn:       mock,
		Attributes: []string{"uid", "mail"},
	}

	ok, user, err := client.Authenticate("testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected authentication to succeed")
	}
	if user["uid"][0] != "testuser" || user["mail"][0] != "test@example.com" {
		t.Errorf("unexpected user attributes: %v", user)
	}
	if mock.boundDN != "uid=testuser,dc=example,dc=com" || mock.boundPWD != "password" {
		t.Errorf("unexpected bind DN or password: %s / %s", mock.boundDN, mock.boundPWD)
	}
}

func TestGetGroupsOfUser_Success(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "cn=group1,dc=example,dc=com",
					Attributes: []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"group1"}},
					},
				},
				{
					DN: "cn=group2,dc=example,dc=com",
					Attributes: []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"group2"}},
					},
				},
			},
		},
	}

	client := &Client{
		Conn: mock,
	}

	groups, err := client.GetGroupsOfUser("testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 || groups[0] != "group1" || groups[1] != "group2" {
		t.Errorf("unexpected groups: %v", groups)
	}
}

func TestConnect_MultiHost(_ *testing.T) {
	// This is harder to test because Connect uses ldap.Dial which we can't easily mock without changing the code further.
	// But we can test the logic of ConnectContext if we extract the dialer.
}
