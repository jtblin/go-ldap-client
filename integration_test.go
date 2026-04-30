//go:build integration

package ldap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
)

func TestIntegrationAuth(t *testing.T) {
	ctx := context.Background()
	_, err := openldap.Run(ctx, "bitnami/openldap:latest")
	assert.NoError(t, err)
}
