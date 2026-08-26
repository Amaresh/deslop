# tsast — AST facts extractor for TypeScript/JavaScript detectors

Parses a single `.ts`/`.tsx`/`.js`/`.jsx` file with the TypeScript compiler
API (`ts.createSourceFile`, `ScriptTarget.Latest`, no Program / no
typecheck) and emits one JSON document of structural facts. Python
detectors consume these facts instead of regexing source text.

## Install

```sh
cd checkers/tsast
npm install
```

`node_modules/` and `package-lock.json` are gitignored.

## Usage

```sh
node facts.mjs path/to/file.ts
node facts.mjs --stdio   # persistent worker: each stdin line is a path, one JSON line out
```

Parse/IO errors go to stderr with exit code 1; usage errors exit 2. `--stdio` writes `null` per failed file and keeps running.

## Output schema

Top level:

| field | type | notes |
|---|---|---|
| `file` | string | path as given on argv |
| `calls` | `[Call]` | every CallExpression |
| `catch_clauses` | `[CatchClause]` | every CatchClause |
| `functions` | `[Function]` | every function-like with a body |
| `binaries` | `[Binary]` | `||` and `??` expressions only |
| `imports` | `[Import]` | static `import` / `export … from` specifiers |
| `jsx` | `[Jsx]` | JSX opening/self-closing elements, plus cheap `createElement`/`jsx`/`jsxs` object-literal props |
| `effects` | `[Effect]` | `useEffect` / `useLayoutEffect` calls |

### Call

| field | notes |
|---|---|
| `name` | last-two-segment callee text (`fetch`, `JSON.parse`, `req.json`) |
| `line` | 1-based |
| `args_summary` | truncated argument source |
| `has_signal_option` | true iff an **argument object literal** has a `signal` property (spreads do not count here) |
| `in_try` | innermost try/catch/finally region is a `try` block |
| `callee_is_local` | identifier `fetch` is bound in this file (not an import of fetch) |
| `resolved_signal` | same-function identifier / spread resolved to an object initialized with `signal` |
| `options_unknown` | options/Request argument not resolvable in-function (unknown ≠ missing) |
| `arg_count` | number of arguments |
| `wrapped_by` | callee name of a parent call this node is an argument of, else `null` |
| `first_arg_kind` | `string_literal` / `identifier` / `call` / `property` / `new` / `template` / `other` |
| `first_arg_name` | identifier or callee name of first arg |
| `stringify_roundtrip` | first arg is `JSON.stringify(...)` |
| `in_handler` | innermost function matches the Express/Koa/Hono handler heuristic |
| `arg_origins` | one-level same-function origin summaries per argument |

### CatchClause

| field | notes |
|---|---|
| `line` | 1-based line of the `catch` keyword |
| `body_empty` | block has no statements (comments / `// ignore` / `;` only) |
| `in_handler` | innermost enclosing function is a handler |
| `param_names` | that function's parameter identifiers |
| `try_has_call` | associated `try` block contains a call, `new`, await, or tagged template |

### Function

| field | notes |
|---|---|
| `name` | identifier, or binding name for `const f = () =>`, else `null` |
| `line_start` | 1-based |
| `params` | top-level identifier parameter names (`this` skipped) |
| `is_handler` | param heuristic **or** callback to `app.get` / `router.post` / `use` / … with a path string |

### Binary

| field | notes |
|---|---|
| `op` | `\|\|` or `??` |
| `line` | 1-based |
| `right_kind` | `number` if the right operand is a numeric literal (optional unary `+/-`) else `other` |
| `right_value` | literal text (`30000`, `-1`) when `right_kind` is `number`, else `null` |
| `left_summary` | truncated left operand source |
| `left_kind` | `identifier` / `property` / `call` / `other` |
| `left_callee` | callee name when `left_kind` is `call`, else `null` |

### Jsx

| field | notes |
|---|---|
| `tag` | element name (`a`, `input`, `Link`, or factory first-arg text) |
| `line` | 1-based |
| `attrs` | `{ name, kind, value_summary, is_expression, has_scheme_allowlist }` |
| `attrs[].kind` | `string_literal` / `template` / `identifier` / `call` / `property` / `other` |
| `attrs[].value_summary` | literal text, template cooked prefix, identifier, or clipped source |
| `attrs[].is_expression` | true for `href={…}` / factory props; false for `href="/x"` |
| `attrs[].has_scheme_allowlist` | enclosing function has `startsWith("http…")` or `/http/` `.test` on that expression |

Spreads (`{...props}`) are omitted (unknown). `jsx("div", { href })` / `React.createElement` with an object-literal second argument are recorded the same way.

### Effect

| field | notes |
|---|---|
| `line` | 1-based line of the `useEffect` / `useLayoutEffect` call |
| `kind` | `useEffect` or `useLayoutEffect` |
| `has_timeout` | first-arg function body (not nested functions) calls `setTimeout` |
| `has_interval` | same, `setInterval` |
| `has_cleanup_timer` | returned cleanup function calls `clearTimeout` / `clearInterval` |
| `has_cleanup_abort` | returned cleanup function calls `abort` |

Timeouts inside nested functions (event handlers) are not counted. Identifier first arguments are not followed.

Handler params: a name in `{req, request, ctx, c}` **and** (`{res, reply, next}` **or** hono `c`).

## Known AST-level limitations

- No type checking: `fetch` vs a same-named local is scope, not types.
- Same-function identifier resolution is one file, one level of aliases.
- `fetch(request)` where `request` is a `Request` is treated as unknown
  (Request may already carry `signal`).
- Imported `fetch` is treated as the global fetch API.
- Parent `schema.parse(JSON.parse(x))` is syntactic; renamed parse helpers
  are not followed.
- JSX spreads and non-literal factory props are omitted (unknown).
- Effect timers inside nested functions (event handlers) are not counted;
  identifier `useEffect(setup)` is not followed.
