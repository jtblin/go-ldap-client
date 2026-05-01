package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const testUserDN = "uid=testuser,dc=example,dc=com"

type mockConn struct {
	bindErr      error
	searchResult *ldap.SearchResult
	searchErr    error
	startTLSErr  error
	closed       bool
	isClosing    bool
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

func (m *mockConn) IsClosing() bool { return m.isClosing }

func TestAuthenticate_EmptyPassword(t *testing.T) {
	client := &Client{}
	ok, _, err := client.Authenticate(context.Background(), "user", "")
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
					DN: testUserDN,
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

	ok, user, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected authentication to succeed")
	}
	if user.Attributes["uid"][0] != "testuser" || user.Attributes["mail"][0] != "test@example.com" {
		t.Errorf("unexpected user attributes: %v", user.Attributes)
	}
	if user.DN != testUserDN {
		t.Errorf("unexpected user DN: %s", user.DN)
	}
	if mock.boundDN != testUserDN || mock.boundPWD != "password" {
		t.Errorf("unexpected bind DN or password: %s / %s", mock.boundDN, mock.boundPWD)
	}
}

func TestConnect_ReconnectOnClose(t *testing.T) {
	mock1 := &mockConn{isClosing: true}
	mock2 := &mockConn{}
	client := &Client{
		Conn: mock1,
		Dialer: func(_ context.Context, _ string, _ *tls.Config) (Conn, error) {
			return mock2, nil
		},
	}

	// This should trigger a new connection because mock1.IsClosing() is true
	err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.Conn != mock2 {
		t.Errorf("expected client.Conn to be mock2, but got %v", client.Conn)
	}
}

func TestGetUser_Success(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: testUserDN,
					Attributes: []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"testuser"}},
					},
				},
			},
		},
	}

	client := &Client{
		Conn:       mock,
		Attributes: []string{"uid"},
	}

	user, err := client.GetUser(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.DN != testUserDN {
		t.Errorf("unexpected DN: %s", user.DN)
	}
	if user.Attributes["uid"][0] != "testuser" {
		t.Errorf("unexpected attribute: %v", user.Attributes["uid"])
	}
}

func TestGetUser_NotFound(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{},
		},
	}

	client := &Client{
		Conn: mock,
	}

	user, err := client.GetUser(context.Background(), "nonexistent")
	if err == nil || err.Error() != "user does not exist" {
		t.Errorf("expected 'user does not exist' error, got %v", err)
	}
	if user != nil {
		t.Error("expected user to be nil")
	}
}

func TestGetUser_TooManyEntries(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{DN: "uid=user1,dc=example,dc=com"},
				{DN: "uid=user2,dc=example,dc=com"},
			},
		},
	}

	client := &Client{
		Conn: mock,
	}

	user, err := client.GetUser(context.Background(), "duplicate")
	if err == nil || err.Error() != "too many entries returned" {
		t.Errorf("expected 'too many entries returned' error, got %v", err)
	}
	if user != nil {
		t.Error("expected user to be nil")
	}
}

func TestAuthenticate_InvalidPassword(t *testing.T) {
	mock := &mockConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{DN: testUserDN},
			},
		},
		// First bind (readonly) succeeds, second bind (user) fails
		bindErr: errors.New("invalid credentials"),
	}

	client := &Client{
		Conn: mock,
	}

	ok, user, err := client.Authenticate(context.Background(), "testuser", "wrongpassword")
	if ok {
		t.Error("expected authentication to fail")
	}
	if err == nil || err.Error() != "invalid credentials" {
		t.Errorf("expected invalid credentials error, got %v", err)
	}
	// We still return the user info even if bind failed (matching current behavior)
	if user == nil || user.DN != testUserDN {
		t.Error("expected user info to be returned")
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

	groups, err := client.GetGroupsOfUser(context.Background(), "testuser")
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
