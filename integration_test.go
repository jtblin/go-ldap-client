//go:build integration

package ldap

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegration(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs("testdata/seed.ldif")
	assert.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ADMIN_PASSWORD": "adminpassword",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ORGANISATION":   "Example",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      absPath,
				ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/seed.ldif",
				FileMode:          0644,
			},
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}
	defer container.Terminate(ctx)

	host, err := container.Host(ctx)
	assert.NoError(t, err)
	port, err := container.MappedPort(ctx, "389/tcp")
	assert.NoError(t, err)

	p, _ := strconv.Atoi(port.Port())

	client := &Client{
		Hosts:        []string{host},
		Base:         "dc=example,dc=org",
		BindDN:       "cn=admin,dc=example,dc=org",
		BindPassword: "adminpassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"uid", "mail", "cn", "sn"},
		Port:         p,
		SkipTLS:      true,
	}

	// Give it extra time to ensure LDIF is processed
	time.Sleep(5 * time.Second)

	// Test Authentication
	t.Run("Authenticate", func(t *testing.T) {
		ok, user, err := client.Authenticate(ctx, "john", "password")
		require.NoError(t, err)
		require.True(t, ok, "authentication should have succeeded")

		assert.Equal(t, "john", user.Attributes["uid"][0])
		assert.Equal(t, "john@example.org", user.Attributes["mail"][0])
		assert.NotEmpty(t, user.DN)
	})

	t.Run("AuthenticateWrongPassword", func(t *testing.T) {
		ok, _, err := client.Authenticate(ctx, "john", "wrong")
		assert.Error(t, err)
		assert.False(t, ok)
	})

	t.Run("AuthenticateEmptyPassword", func(t *testing.T) {
		ok, _, err := client.Authenticate(ctx, "john", "")
		assert.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "authentication failed: empty password")
	})

	t.Run("GetGroupsOfUser", func(t *testing.T) {
		groups, err := client.GetGroupsOfUser(ctx, "john")
		assert.NoError(t, err)
		assert.Contains(t, groups, "admins")
	})
}
