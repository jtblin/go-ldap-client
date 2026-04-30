BIN_DIR := $(CURDIR)/bin
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint

.PHONY: all build test lint fmt clean setup

all: build test lint

build:
	go build ./...

test:
	go test -v -cover ./...

$(GOLANGCI_LINT):
	@echo "Installing golangci-lint..."
	@mkdir -p $(BIN_DIR)
	@GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4

setup: $(GOLANGCI_LINT)
	@echo "Local dev environment setup complete."

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

fmt:
	go fmt ./...

clean:
	go clean
	rm -rf $(BIN_DIR)
	rm -f coverage.out
