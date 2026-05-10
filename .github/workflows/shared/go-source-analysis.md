---
# Go Source Code Analysis Base
# Bundles Serena Go LSP analysis + standard bash permissions for Go source navigation.
#
# Usage:
#   imports:
#     - shared/go-source-analysis.md

imports:
  - shared/mcp/serena-go.md
  - shared/reporting.md

tools:
  bash:
    - "find auth handler maintenance smtp slogcheck -name '*.go' ! -name '*_test.go' -type f"
    - "find auth handler maintenance smtp slogcheck -type f -name '*.go' ! -name '*_test.go'"
    - "find auth/ handler/ maintenance/ smtp/ slogcheck/ -maxdepth 1 -ls"
    - "find auth/ handler/ maintenance/ smtp/ slogcheck/ -name '*.go' -type f | xargs wc -l"
    - "head -n 200 $(find auth handler maintenance smtp slogcheck -name '*.go' ! -name '*_test.go' -type f)"
    - "grep -r 'func ' auth handler maintenance smtp slogcheck --include='*.go'"
    - "cat $(find auth handler maintenance smtp slogcheck -name '*.go' ! -name '*_test.go' -type f)"
---

## Go Source Code Analysis Setup

Serena Go LSP analysis is configured for this workspace. Standard bash tools for Go source navigation are available.

### Bash Navigation Tools

Use these bash tools to supplement Serena's semantic analysis:

- `find auth handler maintenance smtp slogcheck -name '*.go' ! -name '*_test.go' -type f` — list all non-test Go source files
- `find auth/ handler/ maintenance/ smtp/ slogcheck/ -maxdepth 1 -ls` — explore directory structure
- `find ... -name '*.go' -type f | xargs wc -l` — measure file sizes
- `head -n 200 $(find ... -type f)` / `cat $(find ... -type f)` — read file contents
- `grep -r 'func ' auth handler maintenance smtp slogcheck --include='*.go'` — find all function definitions
