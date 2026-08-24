// Command goast-facts parses a Go source file and emits structural JSON
// facts for downstream (Python) detectors. Stdlib only: go/parser + go/ast,
// no type checking.
//
// Usage:
//
//	goast-facts <file.go> [more.go ...]
//
// Prints one indented JSON document per input file, in input order.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
)

const maxSummaryLen = 400

// ---- output schema ----

type StringCmp struct {
	Op       string   `json:"op"` // "==", "!=", "EqualFold", "bytes.Equal", "subtle.ConstantTimeCompare", "hmac.Equal"
	Line     int      `json:"line"`
	Operands []string `json:"operands"`
}

type Call struct {
	Name        string   `json:"name"` // full callee text: "rows.Scan", "db.QueryRow(...).Scan", "http.Get"
	Line        int      `json:"line"`
	ArgsSummary []string `json:"args_summary"`
}

type VarDecl struct {
	Names   []string `json:"names"`
	Type    string   `json:"type"`
	Line    int      `json:"line"`
	Grouped bool     `json:"grouped"` // inside a parenthesized var block, or one spec declaring multiple names
}

type Assign struct {
	Lhs        string `json:"lhs"` // comma-joined lhs expressions
	RhsSummary string `json:"rhs_summary"`
	Line       int    `json:"line"`
}

type Function struct {
	Name              string      `json:"name"`
	Recv              *string     `json:"recv"` // null for plain funcs, "*Type" / "Type" for methods
	LineStart         int         `json:"line_start"`
	LineEnd           int         `json:"line_end"`
	StringComparisons []StringCmp `json:"string_comparisons"`
	Calls             []Call      `json:"calls"`
	GroupedVarDecls   []VarDecl   `json:"grouped_var_decls"`
	Assigns           []Assign    `json:"assigns"`
	Params            []string    `json:"params"`
}

type FieldDetail struct {
	Kind               string `json:"kind"` // "func_literal" | "func_ref" | "expr"
	Summary            string `json:"summary"`
	Lines              []int  `json:"lines,omitempty"`                // func_literal: [start, end]
	RefName            string `json:"ref_name,omitempty"`             // func_ref
	ReturnsLiteralBool *bool  `json:"returns_literal_bool,omitempty"` // func_ref resolution
	AlwaysReturnsTrue  *bool  `json:"always_returns_true,omitempty"`  // func_ref resolution
}

type CompositeLiteral struct {
	Type           string                 `json:"type"`
	Line           int                    `json:"line"`
	Fields         map[string]string      `json:"fields"`
	FieldsDetailed map[string]FieldDetail `json:"fields_detailed,omitempty"`
}

type NamedFunc struct {
	LineStart          int   `json:"line_start"`
	LineEnd            int   `json:"line_end"`
	ReturnsLiteralBool *bool `json:"returns_literal_bool"` // true/false: every return stmt is a single bool literal; null: unknown/none
	AlwaysReturnsTrue  *bool `json:"always_returns_true"`  // true: >=1 return, all literal `true`; else null
}

type Facts struct {
	File              string                `json:"file"`
	Imports           []string              `json:"imports"`
	Functions         []Function            `json:"functions"`
	CompositeLiterals []CompositeLiteral    `json:"composite_literals"`
	NamedFuncsIndex   map[string]*NamedFunc `json:"named_funcs_index"`
}

// ---- extraction state ----

type fileInfo struct {
	fset  *token.FileSet
	funcs map[string]*ast.FuncDecl // plain (non-method) funcs, for one-level ref resolution
	scope map[string]string        // package-level name -> inferred type
}

// ---- small helpers ----

func exprText(fi *fileInfo, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fi.fset, e); err != nil {
		return "<unprintable>"
	}
	return b.String()
}

func trunc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxSummaryLen {
		return s[:maxSummaryLen-3] + "..."
	}
	return s
}

func lineOf(fi *fileInfo, n ast.Node) int {
	return fi.fset.Position(n.Pos()).Line
}

// stringReturningSuffixes: selector-callee suffixes heuristically known to
// return string (stdlib + common REST accessors).
var stringReturningSuffixes = []string{
	".Sprintf", ".Get", ".TrimSpace", ".Trim", ".TrimPrefix", ".TrimSuffix",
	".ToLower", ".ToUpper", ".ToTitle", ".Title", ".Join", ".Repeat",
	".Replace", ".ReplaceAll", ".CutPrefix", ".CutSuffix",
}

// inferType best-effort static type of an expression; "" when unknown.
func inferType(fi *fileInfo, e ast.Expr, scope map[string]string) string {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return inferType(fi, x.X, scope)
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			return "string"
		}
	case *ast.Ident:
		if t, ok := scope[x.Name]; ok {
			return t
		}
	case *ast.CallExpr:
		switch fn := x.Fun.(type) {
		case *ast.Ident:
			switch fn.Name {
			case "string":
				return "string"
			}
		case *ast.SelectorExpr:
			name := exprText(fi, fn)
			for _, suf := range stringReturningSuffixes {
				if strings.HasSuffix(name, suf) {
					return "string"
				}
			}
		}
	}
	return ""
}

// operandText renders an expression as "<kind> <text>" for comparison operands.
func operandText(fi *fileInfo, e ast.Expr) string {
	text := trunc(exprText(fi, e))
	switch x := e.(type) {
	case *ast.ParenExpr:
		return operandText(fi, x.X)
	case *ast.BasicLit:
		return "literal " + text
	case *ast.Ident:
		return "identifier " + text
	case *ast.SelectorExpr:
		return "selector " + text
	case *ast.CallExpr:
		return "call " + text
	default:
		return "other " + text
	}
}

var compareCalls = map[string]string{
	"strings.EqualFold":                 "EqualFold",
	"bytes.Equal":                       "bytes.Equal",
	"crypto/subtle.ConstantTimeCompare": "subtle.ConstantTimeCompare",
	"hmac.Equal":                        "hmac.Equal",
}

func paramTexts(fi *fileInfo, fl *ast.FieldList) []string {
	if fl == nil {
		return nil
	}
	var out []string
	for _, f := range fl.List {
		typ := exprText(fi, f.Type)
		if len(f.Names) == 0 {
			out = append(out, typ)
			continue
		}
		for _, n := range f.Names {
			out = append(out, n.Name+" "+typ)
		}
	}
	return out
}


func bindParams(fi *fileInfo, fl *ast.FieldList, scope map[string]string) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		t := exprText(fi, f.Type)
		for _, nm := range f.Names {
			scope[nm.Name] = t
		}
	}
}

func lhsNames(fi *fileInfo, lhs []ast.Expr) []string {
	out := make([]string, 0, len(lhs))
	for _, e := range lhs {
		switch x := e.(type) {
		case *ast.Ident:
			out = append(out, x.Name)
		default:
			out = append(out, trunc(exprText(fi, e)))
		}
	}
	return out
}

// ---- per-function analysis ----

func analyzeFunc(fi *fileInfo, fd *ast.FuncDecl, fileScope map[string]string) Function {
	fn := Function{Name: fd.Name.Name}
	start, end := lineOf(fi, fd), fi.fset.Position(fd.End()).Line
	fn.LineStart, fn.LineEnd = start, end
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		rt := exprText(fi, fd.Recv.List[0].Type)
		fn.Recv = &rt
	}

	scope := make(map[string]string, len(fileScope)+8)
	for k, v := range fileScope {
		scope[k] = v
	}
	for _, p := range paramTexts(fi, fd.Type.Params) {
		fn.Params = append(fn.Params, p)
	}
	bindParams(fi, fd.Type.Params, scope)

	recordCmp := func(op string, line int, operands ...string) {
		fn.StringComparisons = append(fn.StringComparisons, StringCmp{
			Op: op, Line: line, Operands: operands,
		})
	}

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			// Descend: statements inside handler-style closures (e.g.
			// http.HandlerFunc(func(...) {...})) belong to the enclosing
			// function for detection purposes. Bind closure params to scope.
			bindParams(fi, x.Type.Params, scope)
			return true

		case *ast.GenDecl:
			if x.Tok != token.VAR {
				return true
			}
			grouped := x.Lparen.IsValid() || len(x.Specs) > 1
			for _, s := range x.Specs {
				vs := s.(*ast.ValueSpec)
				typ := ""
				if vs.Type != nil {
					typ = exprText(fi, vs.Type)
				} else if len(vs.Values) == 1 {
					typ = inferType(fi, vs.Values[0], scope)
				}
				names := lhsNames(fi, specsIdents(vs.Names))
				fn.GroupedVarDecls = append(fn.GroupedVarDecls, VarDecl{
					Names:   names,
					Type:    typ,
					Line:    lineOf(fi, vs),
					Grouped: grouped || len(names) > 1,
				})
				for _, nm := range names {
					scope[nm] = typ
				}
			}
			return false

		case *ast.AssignStmt:
			rhsTxts := make([]string, 0, len(x.Rhs))
			for _, r := range x.Rhs {
				rhsTxts = append(rhsTxts, trunc(exprText(fi, r)))
			}
			fn.Assigns = append(fn.Assigns, Assign{
				Lhs:        strings.Join(lhsNames(fi, x.Lhs), ", "),
				RhsSummary: strings.Join(rhsTxts, ", "),
				Line:       lineOf(fi, x),
			})
			// scope update for := and = with positionally matched rhs
			if len(x.Lhs) == len(x.Rhs) {
				for i := range x.Lhs {
					if id, ok := x.Lhs[i].(*ast.Ident); ok {
						if t := inferType(fi, x.Rhs[i], scope); t != "" {
							scope[id.Name] = t
						}
					}
				}
			}
			return true

		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				op := "=="
				if x.Op == token.NEQ {
					op = "!="
				}
				if inferType(fi, x.X, scope) == "string" || inferType(fi, x.Y, scope) == "string" {
					recordCmp(op, lineOf(fi, x), operandText(fi, x.X), operandText(fi, x.Y))
				}
			}
			return true

		case *ast.CallExpr:
			full := exprText(fi, x.Fun)
			args := make([]string, 0, len(x.Args))
			for _, a := range x.Args {
				args = append(args, trunc(exprText(fi, a)))
			}
			fn.Calls = append(fn.Calls, Call{
				Name:        trunc(full),
				Line:        lineOf(fi, x),
				ArgsSummary: args,
			})
			if op, ok := compareCalls[full]; ok {
				ops := make([]string, 0, 2)
				for i := 0; i < len(x.Args) && i < 2; i++ {
					ops = append(ops, operandText(fi, x.Args[i]))
				}
				recordCmp(op, lineOf(fi, x), ops...)
			}
			return true
		}
		return true
	})

	if fn.StringComparisons == nil {
		fn.StringComparisons = []StringCmp{}
	}
	if fn.Calls == nil {
		fn.Calls = []Call{}
	}
	if fn.GroupedVarDecls == nil {
		fn.GroupedVarDecls = []VarDecl{}
	}
	if fn.Assigns == nil {
		fn.Assigns = []Assign{}
	}
	return fn
}

func specsIdents(idents []*ast.Ident) []ast.Expr {
	out := make([]ast.Expr, 0, len(idents))
	for _, id := range idents {
		out = append(out, id)
	}
	return out
}

// ---- return-shape analysis ----

func returnInfo(fi *fileInfo, fd *ast.FuncDecl) (*bool, *bool) {
	if fd.Body == nil {
		return nil, nil
	}
	var rets []*ast.ReturnStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if rs, ok := n.(*ast.ReturnStmt); ok {
			rets = append(rets, rs)
		}
		return true
	})
	if len(rets) == 0 {
		return nil, nil
	}
	allBool := true
	allTrue := true
	for _, rs := range rets {
		lit := ""
		if len(rs.Results) == 1 {
			if id, ok := rs.Results[0].(*ast.Ident); ok && (id.Name == "true" || id.Name == "false") {
				lit = id.Name
			}
		}
		if lit == "" {
			allBool = false
			allTrue = false
		}
		if lit != "true" {
			allTrue = false
		}
	}
	return &allBool, &allTrue
}

// ---- file-level extraction ----

func extractFile(path string) (*Facts, error) {
	fi := &fileInfo{fset: token.NewFileSet()}
	f, err := parser.ParseFile(fi.fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	facts := &Facts{
		File:              path,
		Imports:           []string{},
		Functions:         []Function{},
		CompositeLiterals: []CompositeLiteral{},
		NamedFuncsIndex:   map[string]*NamedFunc{},
	}

	fi.funcs = map[string]*ast.FuncDecl{}
	fi.scope = map[string]string{}

	for _, imp := range f.Imports {
		facts.Imports = append(facts.Imports, strings.Trim(imp.Path.Value, `"`))
	}

	// Pass 1: package-level decls (consts/vars for type scope, funcs for refs).
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		isVar := gd.Tok == token.VAR
		isConst := gd.Tok == token.CONST
		if !isVar && !isConst {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			typ := ""
			if vs.Type != nil {
				typ = exprText(fi, vs.Type)
			} else if len(vs.Values) == 1 {
				typ = inferType(fi, vs.Values[0], fi.scope)
			}
			for _, nm := range vs.Names {
				if typ != "" {
					fi.scope[nm.Name] = typ
				}
			}
		}
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
			fi.funcs[fd.Name.Name] = fd
		}
	}

	// Pass 2: named_funcs_index (funcs + methods).
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		key := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			key = exprText(fi, fd.Recv.List[0].Type) + "." + fd.Name.Name
		}
		rlb, art := returnInfo(fi, fd)
		facts.NamedFuncsIndex[key] = &NamedFunc{
			LineStart:          lineOf(fi, fd),
			LineEnd:            fi.fset.Position(fd.End()).Line,
			ReturnsLiteralBool: rlb,
			AlwaysReturnsTrue:  art,
		}
	}

	// Pass 3: functions.
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		facts.Functions = append(facts.Functions, analyzeFunc(fi, fd, fi.scope))
	}

	// Pass 4: composite literals anywhere in the file.
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || cl.Type == nil {
			return true
		}
		comp := CompositeLiteral{
			Type:           exprText(fi, cl.Type),
			Line:           lineOf(fi, cl),
			Fields:         map[string]string{},
			FieldsDetailed: map[string]FieldDetail{},
		}
		details := map[string]FieldDetail{}
		for i, e := range cl.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				key := fmt.Sprintf("[%d]", i)
				sum := trunc(exprText(fi, e))
				comp.Fields[key] = sum
				details[key] = FieldDetail{Kind: "expr", Summary: sum}
				continue
			}
			key := trunc(exprText(fi, kv.Key))

			switch v := kv.Value.(type) {
			case *ast.FuncLit:
				a, b := lineOf(fi, v), fi.fset.Position(v.End()).Line
				sum := fmt.Sprintf("func-literal lines %d-%d", a, b)
				comp.Fields[key] = sum
				details[key] = FieldDetail{Kind: "func_literal", Summary: sum, Lines: []int{a, b}}
			case *ast.Ident:
				if target, ok := fi.funcs[v.Name]; ok && target.Body != nil {
					nf := facts.NamedFuncsIndex[v.Name]
					sum := fmt.Sprintf("ref %s lines %d-%d", v.Name, nf.LineStart, nf.LineEnd)
					comp.Fields[key] = sum
					fd2 := FieldDetail{Kind: "func_ref", Summary: sum, RefName: v.Name}
					if target.Body != nil {
						fd2.ReturnsLiteralBool = nf.ReturnsLiteralBool
						fd2.AlwaysReturnsTrue = nf.AlwaysReturnsTrue
					}
					details[key] = fd2
				} else {
					sum := trunc(exprText(fi, kv.Value))
					comp.Fields[key] = sum
					details[key] = FieldDetail{Kind: "expr", Summary: sum}
				}
			default:
				sum := trunc(exprText(fi, kv.Value))
				comp.Fields[key] = sum
				details[key] = FieldDetail{Kind: "expr", Summary: sum}
			}
		}
		comp.FieldsDetailed = details
		facts.CompositeLiterals = append(facts.CompositeLiterals, comp)
		return true
	})

	return facts, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goast-facts <file.go> [more.go ...]")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	exit := 0
	for _, path := range os.Args[1:] {
		facts, err := extractFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "goast-facts: %s: %v\n", path, err)
			exit = 1
			continue
		}
		if err := enc.Encode(facts); err != nil {
			fmt.Fprintf(os.Stderr, "goast-facts: encode: %v\n", err)
			exit = 1
		}
	}
	os.Exit(exit)
}
