# go-ldap-client Workspace Instructions

## Project Overview
A simple LDAP client for Go to authenticate users, retrieve basic information, and fetch groups.

## Project Structure
- `ldap-client.go`: Main library implementation.
- `cmd/main.go`: CLI tool example/usage.
- `*_test.go`: Unit and integration tests.
- `testdata/`: LDIF files for testing.
- `bin/`: Local tools (e.g., `golangci-lint`).

## Build & Test Commands
- `rtk make build`: Build the project.
- `rtk make test`: Run unit tests.
- `rtk make test-integration`: Run integration tests (requires Docker).
- `rtk make test-all`: Run all tests.
- `rtk make lint`: Run linters.
- `rtk make fmt`: Format code.

## Workflows
- `sync-docs`: Update and maintain GEMINI.md and README.md documentation.
- `release-management`: Analyze changes, generate notes, and manage GitHub releases.
- `smart-commit`: Generate conventional commit messages and enforce atomic commits.

## Coding Patterns
- **Context Support**: All methods require `context.Context`.
- **Error Handling**: Use wrapped errors (`fmt.Errorf("...: %w", err)`).
- **LDAP Interface**: Use the `Conn` interface for mocking LDAP connections.
- **Failover**: Supports multiple hosts via the `Hosts` field in `Client`.

## Environment Setup
- Go 1.26+
- Docker (for integration tests using Testcontainers)
