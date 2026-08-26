# deslop

Rules your coding agents read **before** they write code — across
**Java/Spring**, **Python/FastAPI**, **TypeScript/Node/React**, **Go**,
and **Android**. CI gates the patterns we can *prove* agents emit.

Most tools comment on a pull request after the damage is done. deslop
puts a small pack of invariants in the agent's context first, then runs a
deterministic checker on the subset with verified detectors.

```mermaid
flowchart LR
  subgraph beforeWrite [Before the agent writes]
    A["Your repo"] --> B["deslop skills"]
    B --> C["Agent reads rule"]
    C --> D["Code follows it"]
  end
  subgraph afterSlip [If it still slips]
    D --> E["deslop check"]
    E -->|"checker"| F["Build fails"]
    E -->|"teach-only"| G["Warn only"]
  end
```

## Stacks

Five packs ship in this repo. `deslop learn` also profiles **Go**.

| Pack | Languages / frameworks | Rules | CI today |
|---|---|---|---|
| [`deslop-java-spring`](skills/deslop-java-spring/SKILL.md) | Java, Spring, JPA | 11 | **11 checkers** |
| [`deslop-python-fastapi`](skills/deslop-python-fastapi/SKILL.md) | Python, FastAPI, Pydantic, httpx | 13 | **8 checkers**, 5 teach-only |
| [`deslop-ts-node`](skills/deslop-ts-node/SKILL.md) | TypeScript, Node, Express, React | 12 | **8 checkers**, 4 teach-only |
| [`deslop-go`](skills/deslop-go/SKILL.md) | Go, net/http, database/sql | 8 | **8 checkers** |
| [`deslop-android`](skills/deslop-android/SKILL.md) | Kotlin, Android, Compose | 3 | **3 checkers** |
| `deslop learn` | Go, Python, TypeScript, Java | — | measures conventions; does not install a pack |

```mermaid
flowchart TB
  subgraph available [What you can use today]
    J["Java / Spring<br/>install + 11 CI gates"]
    P["Python / FastAPI<br/>8 CI gates + 5 teach"]
    T["TypeScript / Node<br/>8 CI gates + 4 teach"]
    G["Go<br/>8 CI gates"]
    A["Android<br/>3 CI gates"]
  end
  subgraph discover [What you can measure]
    L["deslop learn<br/>Go, Python, TS, Java"]
  end
  available --> discover
```

`deslop install` writes the **Java/Spring** pack-index into a target repo.
Python, TypeScript, Go, and Android packs live as skills here — copy the
pack-index directory plus its `no-*` skills into your agent's layout (see
[Using a pack](#using-a-pack)). Multi-pack install is not wired yet; do
not pretend `deslop install` drops FastAPI or Node rules into a repo.

`deslop check` **does** run every pack whose language is present in the
repo. Pass `--pack python` (or `ts`, `go`, `android`, `java`) to scope it.

## How a rule reaches CI

An invariant is a property that must always hold. Every rule starts as
**teach-only** (steering). It becomes **checker** after a detector exists
and OSS benches show **0 unjustified false positives**.

```mermaid
flowchart TD
  I["Must always hold"] --> S["Skill in the pack"]
  S --> T["teach-only"]
  T --> D["Detector exists"]
  D --> V["0 unjustified FPs<br/>on OSS bench"]
  V --> C["checker<br/>CI fails the build"]
  T -.->|"no detector yet"| Stay["Stays teach-only"]
```

The gated checkers are portable AST detectors under `checkers/`. They are
not Motorrad house rules (no web-layer folder names, no service-locator
bans, no blanket `no-use-effect`). The original three Java engine rules
(JPQL, RestTemplate timeouts, `@Transactional` IO) stay on the Java
engine so existing CI keeps the same findings.

## Pack contents

### Java / Spring

| Rule | Enforcement | Invariant |
|---|---|---|
| `no-jpql-null-or-lower` | **checker** | No `:param IS NULL OR` combined with `LOWER` on optional JPQL filters |
| `no-transactional-external-io` | **checker** | No HTTP / S3 / messaging inside `@Transactional` |
| `no-rest-template-without-timeout` | **checker** | No `new RestTemplate()` without `setRequestFactory` timeout shaping |
| `no-n-plus-one-without-entity-graph` | **checker** | No collection finder + lazy to-many in a loop without a fetch graph |
| `no-query-string-concatenation` | **checker** | No JPQL/SQL built with `+` concatenation |
| `no-file-upload-without-validation` | **checker** | Uploads get size/type checks |
| `no-secret-fallback-literal` | **checker** | No secret string fallback when env is missing |
| `no-java-raw-pii-logging` | **checker** | No raw email/phone in logs |
| `no-eager-to-many-fetch` | **checker** | No `FetchType.EAGER` on to-many associations |
| `no-controller-direct-repository-access` | **checker** | Controllers do not inject repositories |
| `no-unbounded-findall-without-pagination` | **checker** | No unbounded `findAll()` on a request path |

Java AST checkers need **JDK 21** (`javac` / `java`). JavaParser is fetched
once and SHA-256 pinned.

### Python / FastAPI

Pack index: [`skills/deslop-python-fastapi`](skills/deslop-python-fastapi/SKILL.md).

| Rule | Enforcement | Invariant |
|---|---|---|
| `no-sync-blocking-io-in-async-route` | **checker** | No sync blocking I/O inside `async def` routes |
| `no-httpx-asyncclient-without-timeout` | **checker** | `httpx.AsyncClient` gets an explicit `timeout=` |
| `no-except-exception-pass` | **checker** | No `except Exception: pass` |
| `no-dynamic-sql-execution` | **checker** | Bound parameters, not f-string / concat SQL |
| `no-route-request-json-without-invalid-json-guard` | **checker** | Guard `request.json` on untrusted bodies |
| `no-raw-pii-logging` | **checker** | No raw email/phone in logs |
| `no-request-layer-outbound-client-construction` | **checker** | Do not construct HTTP clients inside routes |
| `no-requests-call-without-timeout` | **checker** | Every `requests` call has `timeout=` |
| `no-fstring-sql-interpolation` | teach-only | Prefer bound parameters (overlap with dynamic SQL) |
| `no-post-validation-model-mutation` | teach-only | Do not mutate Pydantic fields after validation |
| `no-fire-and-forget-task-without-cancellation` | teach-only | Keep a reference; handle cancellation |
| `no-secret-defaults-in-settings` | teach-only | No secrets as settings / signature defaults |
| `no-route-without-response-model` | teach-only | Declare `response_model=` |

### TypeScript / Node / React

Pack index: [`skills/deslop-ts-node`](skills/deslop-ts-node/SKILL.md).
Needs **Node + npm** (TypeScript parser under `checkers/tsast`).

| Rule | Enforcement | Invariant |
|---|---|---|
| `no-fetch-without-abort-timeout` | **checker** | Pair `fetch` with an abort timeout |
| `no-empty-catch-in-express-handlers` | **checker** | Catch, log, and return an error response |
| `no-unguarded-json-parse-on-external-input` | **checker** | Guard `JSON.parse` on external text |
| `no-mixed-controlled-react-inputs` | **checker** | Controlled or uncontrolled, never mixed |
| `no-unvalidated-external-href` | **checker** | Allowlist `http(s)` before `href={expr}` |
| `no-orphaned-effect-timeouts` | **checker** | Clear effect timers on cleanup |
| `no-eager-heavy-dependency-import` | **checker** | Do not statically import lodash/moment-class libs |
| `no-or-default-for-nonzero-number` | **checker** | Do not `n \|\| 20` when 0 is valid |
| `no-floating-promises` | teach-only | Await or handle every promise (needs types) |
| `no-unvalidated-env-at-module-top-level` | teach-only | Lazy, validated env |
| `no-non-null-array-index` | teach-only | Bounds-check; do not silence with `!` |
| `no-setinterval-without-clear` | teach-only | Store the handle and clear it |

### Go

Pack index: [`skills/deslop-go`](skills/deslop-go/SKILL.md). Needs **Go 1.21+**.

| Rule | Enforcement | Invariant |
|---|---|---|
| `no-plain-string-secret-comparison` | **checker** | Constant-time secret compare |
| `no-go-dynamic-sql-execution` | **checker** | Bound parameters, not `fmt.Sprintf` SQL |
| `no-handler-detached-goroutine` | **checker** | No detached `go` from a handler |
| `no-handler-direct-sql-execution` | **checker** | Handlers do not run SQL |
| `no-handler-direct-outbound-http` | **checker** | Handlers do not `http.Get` |
| `no-handler-rooted-background-context` | **checker** | Use `r.Context()`, not `context.Background()` |
| `no-nullable-column-scanned-as-plain-value` | **checker** | Scan nullable columns into `sql.Null*` |
| `no-websocket-upgrader-checkorigin-allow-all` | **checker** | `CheckOrigin` must not always return true |

### Android

Pack index: [`skills/deslop-android`](skills/deslop-android/SKILL.md).

| Rule | Enforcement | Invariant |
|---|---|---|
| `no-hardcoded-secret-literals` | **checker** | No API keys as string literals |
| `no-unscoped-boundary-coroutine` | **checker** | No `GlobalScope` at UI boundaries |
| `no-runblocking-hotpath` | **checker** | No `runBlocking` on the UI path |

## Using a pack

```mermaid
flowchart TD
  Clone["Clone deslop"] --> Pick{"Which stack?"}
  Pick -->|"Java / Spring"| Inst["deslop install"]
  Pick -->|"Python / FastAPI"| CopyP["Copy Python skills"]
  Pick -->|"TypeScript / Node"| CopyT["Copy TS skills"]
  Pick -->|"Go"| CopyG["Copy Go skills"]
  Pick -->|"Android"| CopyA["Copy Android skills"]
  Inst --> CI["deslop check"]
  CopyP --> CI
  CopyT --> CI
  CopyG --> CI
  CopyA --> CI
```

### Check any stack (CI)

```bash
git clone https://github.com/Amaresh/deslop && cd deslop
pip install -e .            # engine + deps (pydantic, PyYAML)

# Inspect packs (writes nothing)
python3 scripts/deslop.py review

# Auto-detect languages in the repo and gate their checkers
python3 scripts/deslop.py check --repo-root /path/to/your/repo

# Or pin a pack
python3 scripts/deslop.py check --repo-root /path/to/your/repo --pack python
```

### Java / Spring (install + CI)

```bash
python3 scripts/deslop.py install --target /path/to/your/repo
```

Install writes one namespaced pack-index skill
(`skills/deslop/deslop-java-spring/`) into the target's `.agents/skills/`
layout plus reference files, reports collisions with existing agent
instructions, pins the installed version for `update`/`rollback`, and never
dumps sibling skills.

```bash
scripts/ci.sh /path/to/your/repo   # exit 1 on checker findings only
```

See [`ci/github-action.yml.example`](ci/github-action.yml.example) for a
GitHub Actions setup (Python plus JDK / Node / Go when those stacks are
present).

### Python, TypeScript, Go, or Android (skills in this repo)

There is no `deslop install --pack python` yet. To steer an agent:

1. Copy the pack-index folder (`skills/deslop-python-fastapi/`,
   `skills/deslop-ts-node/`, `skills/deslop-go/`, or
   `skills/deslop-android/`).
2. Copy each `skills/no-*` directory listed in that pack's `pack.yaml`.
3. Point your harness at those skills the same way you would any other
   SKILL.md pack.

`deslop check --pack <alias>` still gates the checker rules even if you
never install the skills.

## deslop learn — extract the rules a codebase already follows

`deslop learn` measures the conventions a repository actually follows (and
the ones it keeps violating), then emits candidate rules with evidence.
Works on **Go, Python, TypeScript, and Java**.

```bash
python3 scripts/learn.py --repo /path/to/repo --lang go --out learn-out
```

```mermaid
flowchart TD
  R["Repository"] --> T1["Tier 1 counters"]
  T1 --> T2["Tier 2 induction"]
  T2 --> C["Candidates + cites"]
  C --> H["teach-only until<br/>a detector catches it"]
```

Learn is the "find rules" counterpart to "apply rules": point it at a repo
and it tells you what that repo would teach a new contributor.

## What deslop is not

- Not an AI code reviewer. It does not comment on pull requests or scan
  diffs after the fact; it shapes what the agent writes and gates a
  verified subset deterministically.
- No auto-attach guarantees. Whether your agent loads the installed skill
  depends on your harness; discovery behavior varies.
- Teach rules are not gates and must not be sold as gates.
- Not "works on any Spring / FastAPI / Node repo." Packs are small and
  specific. Java, Python, TypeScript, Go, and Android each gate the
  subset with 0 unjustified OSS false positives.

## License

MIT
