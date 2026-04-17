.PHONY: all build frontend backend clean dev redis-check screenshots kill-dev swagger swagger-fmt docs-serve lint-errorf

# Tooling commands
SWAG_CMD = go run github.com/swaggo/swag/v2/cmd/swag@v2.0.0-rc5
GOLANGCI_LINT_CMD = go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@1c222b488bbc2c0ae2cad8423a24b8452f2fc3a9

# Build everything: frontend then Go binary
all: build

lint:
	$(GOLANGCI_LINT_CMD) run ./... --max-issues-per-linter 0 --max-same-issues 0

fmt:
	go fmt ./...

hardfmt:
	go tool gofumpt -w -l .

test:
	go test -v ./...

testsum:
	gotestsum -- -v ./...

modernize:
	go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -fix  ./...