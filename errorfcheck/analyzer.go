// Package errorfcheck provides a go/analysis Analyzer that reports calls to
// [fmt.Errorf] whose format string contains no format verbs.  Such calls
// should use [errors.New] instead, because fmt.Errorf with a static string
// is unnecessary overhead and obscures intent.
package errorfcheck

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the errorfcheck analysis.Analyzer.
var Analyzer = &analysis.Analyzer{
	Name:     "errorfcheck",
	Doc:      "reports fmt.Errorf calls whose format string has no format verbs (use errors.New instead)",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}

	// Build set of generated files to skip using the stdlib check.
	generated := make(map[string]bool)
	for _, f := range pass.Files {
		if ast.IsGenerated(f) {
			generated[pass.Fset.Position(f.Pos()).Filename] = true
		}
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}

		// Skip generated files.
		pos := pass.Fset.Position(call.Pos())
		if generated[pos.Filename] {
			return
		}

		if !isFmtErrorf(pass, call) {
			return
		}

		// fmt.Errorf(format, args...) — check the format argument (index 0).
		if len(call.Args) == 0 {
			return
		}

		fmtStr, ok := stringLitValue(pass, call.Args[0])
		if !ok {
			return
		}

		if !hasFormatVerb(fmtStr) {
			if len(call.Args) > 1 {
				pass.Reportf(call.Pos(), "fmt.Errorf format string has no verbs but has extra arguments; add format verbs (e.g. %%w) or remove extra arguments")
			} else {
				pass.Reportf(call.Pos(), "fmt.Errorf with no format verbs; use errors.New instead")
			}
		}
	})

	return nil, nil
}

// isFmtErrorf reports whether call is an invocation of the fmt package-level
// Errorf function.
func isFmtErrorf(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Errorf" {
		return false
	}
	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil {
		return false
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	pkg := fn.Pkg()
	return pkg != nil && pkg.Path() == "fmt"
}

// stringLitValue returns the unquoted value of a string literal expression or
// a named constant of type string.  It returns ("", false) for all other
// expression kinds.
func stringLitValue(pass *analysis.Pass, expr ast.Expr) (string, bool) {
	// Direct string literal.
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "", false
		}
		return s, true
	}

	// Named constant (e.g. const errMsg = "...").
	if ident, ok := expr.(*ast.Ident); ok {
		obj := pass.TypesInfo.Uses[ident]
		if obj == nil {
			return "", false
		}
		c, ok := obj.(*types.Const)
		if !ok {
			return "", false
		}
		if basic, ok := c.Type().Underlying().(*types.Basic); ok && basic.Info()&types.IsString != 0 {
			s, err := strconv.Unquote(c.Val().ExactString())
			if err != nil {
				return "", false
			}
			return s, true
		}
	}

	return "", false
}

// hasFormatVerb reports whether s contains at least one Go format verb
// (a '%' that is not part of a '%%' literal-percent escape).
func hasFormatVerb(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		// Check for escaped percent '%%'.
		if i+1 < len(s) && s[i+1] == '%' {
			i++ // skip the second '%'
			continue
		}
		// A lone '%' at end of string is malformed (not a real verb), but we
		// treat it conservatively — if there's any unescaped '%', we assume the
		// caller may have intended a verb and skip the report to avoid false positives.
		return true
	}
	return false
}
