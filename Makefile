.PHONY: all lint lint-require lint-errorfcheck fmt hardfmt test testsum modernize

# Tooling commands
GOLANGCI_LINT_CMD = go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@1c222b488bbc2c0ae2cad8423a24b8452f2fc3a9

# Build everything: frontend then Go binary
all: lint fmt test

lint:
	$(GOLANGCI_LINT_CMD) run ./... --max-issues-per-linter 0 --max-same-issues 0
	$(MAKE) lint-require
	$(MAKE) lint-errorfcheck

lint-errorfcheck:
	go run ./cmd/errorfcheck ./...

lint-require:
	@files=$$(git ls-files '*_test.go'); \
	if [ -z "$$files" ]; then \
		echo "No test files found."; \
		exit 0; \
	fi; \
	if grep -nE '(\bt\.(Error|Errorf|Fatal|Fatalf)\()|(^|[^[:alnum:]_])assert\.' $$files; then \
		echo "Found forbidden test assertions. Use testify/require only."; \
		exit 1; \
	fi

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