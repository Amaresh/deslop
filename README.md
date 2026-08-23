# deslop

Rules your coding agents read **before** they write code — plus CI gates for
the patterns we can prove agents emit.

deslop ships a pack of engineering invariants as small skill files (with a
pack index), an installer that drops them into your repo's agent-rules layout,
and a deterministic checker that gates the subset of rules with verified
detectors.

## Honest status

Every rule is `teach-only` (steering) unless marked `checker` in `pack.yaml`.

| Rule | Ecosystem | Enforcement | Invariant |
|---|---|---|---|
| `no-jpql-null-or-lower` | Java/Spring | **checker** | No `:param IS NULL OR` combined with `LOWER` on optional JPQL filters; use an empty-string sentinel |
| `no-transactional-external-io` | Java/Spring | teach-only | No HTTP / S3 / messaging calls inside `@Transactional` methods; persist, commit, then send |
| `no-rest-template-without-timeout` | Java/Spring | teach-only | No `new RestTemplate()` without `setRequestFactory` timeout shaping |

Teach rules are opinionated defaults. A rule earns `checker` status only when
an agent-written violation sample fails its detector — see
[docs/composer-experiment.md](docs/composer-experiment.md) for the evidence
behind the first one.

## Quickstart

```bash
git clone https://github.com/Amaresh/deslop && cd deslop
pip install -e .            # engine + deps (pydantic, PyYAML)

# Inspect the pack (writes nothing)
python3 scripts/deslop.py review

# Check any Java/Spring repo for checker-rule violations
python3 scripts/deslop.py check --repo-root /path/to/your/repo

# Install into a target repo (refuses if it already has agent rules; --force to override)
python3 scripts/deslop.py install --target /path/to/your/repo
```

Install writes one namespaced pack-index skill (`skills/deslop/deslop-java-spring/`)
into the target's `.agents/skills/` layout plus reference files, reports
collisions with existing agent instructions, pins the installed version for
`update`/`rollback`, and never dumps sibling skills.

### CI

```bash
scripts/ci.sh /path/to/your/repo   # exit 1 on checker findings only
```

See [`ci/github-action.yml.example`](ci/github-action.yml.example) for a GitHub
Actions setup.

## How rules earn `checker`

A rule is promoted from teach-only only after:

1. A detector exists for it.
2. An independently produced agent-written code sample fails that detector.

Everything else stays teach-only: it may steer an agent that reads it, but CI
must not fail on it.

## What deslop is not

- Not an AI code reviewer. deslop does not comment on pull requests or scan
  diffs after the fact; it shapes what the agent writes and gates a verified
  subset deterministically.
- No auto-attach guarantees. Whether your agent loads the installed skill
  depends on your harness; discovery behavior varies.
- Teach rules are not gates and must not be sold as gates.

## License

MIT
