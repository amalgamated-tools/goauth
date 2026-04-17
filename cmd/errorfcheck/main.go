// Command errorfcheck runs the errorfcheck analyzer over the provided packages.
// Usage:
//
//	go run ./cmd/errorfcheck ./...
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/amalgamated-tools/goauth/errorfcheck"
)

func main() {
	singlechecker.Main(errorfcheck.Analyzer)
}
