# goast — AST facts extractor for stopthatslop detectors

Stdlib-only Go helper (`go/parser` + `go/ast`, no type checking) that parses a
Go source file and emits structural JSON facts. Python detectors (G2 rewrite,
see `docs/plans/2026-08-24-phase-g-mining-gate.md` §G2) consume these facts
instead of regexing source text.

## Build

Vendored toolchain (no system Go required):

```sh
cd checkers/goast
export GOROOT=/tmp/opencode/go-root
export GOPATH=/tmp/opencode/gopath
export PATH=/tmp/opencode/go-root/bin:$PATH
go build -o goast-facts main.go   # goast-facts is gitignored
```

## Usage

```sh
./goast-facts path/to/file.go            # one indented JSON doc per file
./goast-facts a.go b.go                  # multiple files, input order
python3 smoke_check.py                   # run the fact assertions over testdata/
```

Parse errors go to stderr with exit code 1; usage errors exit 2.

## Output schema

Top level:

| field | type | notes |
|---|---|---|
| `file` | string | path as given on argv |
| `imports` | `[string]` | import paths, quotes stripped |
| `functions` | `[Function]` | every top-level func/method **with a body** |
| `composite_literals` | `[CompositeLiteral]` | all typed composite literals in the file |
| `named_funcs_index` | `map[string]NamedFunc` | key = plain name; methods keyed `"*Recv.Method"` |

### Function

| field | type | notes |
|---|---|---|
| `name`, `recv`, `line_start`, `line_end` | | `recv` is `null` or e.g. `"*Store"` |
| `string_comparisons` | `[StringCmp]` | see below |
| `calls` | `[Call]` | `{name, line, args_summary}`; `name` is the full callee text, so chained calls appear as `db.QueryRow(\`...\`).Scan` — this ties a Scan to its statement |
| `grouped_var_decls` | `[VarDecl]` | every function-body `var` spec: `{names, type, line, grouped}`; `grouped=true` when inside a parenthesized block or one spec declares several names (`var id, bikeID int64`) |
| `assigns` | `[Assign]` | `{lhs, rhs_summary, line}`; lhs comma-joined for multi-assign |
| `go_stmts` | `[GoStmt]` | `{line, call_summary, has_context}` for each `go` statement; `call_summary` is the launched `CallExpr` (func-lit body included); `has_context` is true when that text contains `Context()`, `.Done()`, or ident `ctx` |

### StringCmp

`{op, line, operands}` where operands are kind-tagged strings:
`identifier x`, `literal ""`, `selector r.Header.Get("X-Token")`,
`call tokenOf(r)`, `other &x`.

- `op == "==" / "!="`: emitted only when at least one operand infers as
  `string` (string literal, explicitly typed var/param/const, or a call whose
  callee matches known string-returning suffixes like `.Get`, `.TrimSpace`,
  `.Sprintf`). Non-string comparisons (`err == sql.ErrNoRows`, int compares)
  are excluded.
- `op == "EqualFold" | "bytes.Equal" | "subtle.ConstantTimeCompare" | "hmac.Equal"`:
  comparison-shaped stdlib calls; operands are the first two args.

### CompositeLiteral

| field | notes |
|---|---|
| `type`, `line` | e.g. `"websocket.Upgrader"` |
| `fields` | key → summary string; func-literal values become `"func-literal lines 13-15"`, named-func refs become `"ref isValidOrigin lines 23-25"` |
| `fields_detailed` | key → `{kind, summary}` with extras: func_literal adds `lines:[a,b]`; func_ref adds `ref_name`, plus resolved `returns_literal_bool` and `always_returns_true` from `named_funcs_index` (one-level resolution, same file only) |

### NamedFunc

`{line_start, line_end, returns_literal_bool, always_returns_true}`

- `returns_literal_bool`: `true`/`false` when the body has returns and **every**
  return statement is a single bool literal; `null` otherwise.
- `always_returns_true`: `true` only when there is ≥1 return and all are
  literal `true`; otherwise `null`. (The CheckOrigin allow-all signal.)

## Known AST-level limitations

- No type checking: inference is syntactic heuristics. Unknown-typed operands
  are excluded from `==`/`!=` facts rather than guessed (deliberate FP bias).
- Import aliasing breaks the compare-call table: `import str "strings"` then
  `str.EqualFold(...)` is not recognized (recorded only as a plain call).
- Named-func resolution in `fields_detailed` is same-file, one level deep
  (`CheckOrigin: helperFn` resolves; `CheckOrigin: wrap(helperFn)` does not).
- Method values / interface dispatch are not followed; `s.Get("k")` is typed
  string by suffix heuristic regardless of `s`'s real type.
- Const tracking is package-level + explicit types only; `const x = y` chains
  inherit no type.
- Nested func literals inside ordinary functions are skipped during per-function
  analysis (their bodies surface via the composite-literal pass when embedded).
