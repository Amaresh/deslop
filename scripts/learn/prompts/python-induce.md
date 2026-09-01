# LLM induction prompt — Python conventions (deslop learn, tier 2)

You are analyzing a Python codebase to infer its IMPLICIT rules —
conventions the code consistently follows that were never written down.
This output becomes candidate rules for a stopthatslop pack.

You are given: a sample of ~30 representative source files from the repo
(with relative paths). You do NOT see the whole repo.

## Your task

Propose up to 8 conventions that this codebase appears to follow or violate,
in this exact YAML shape per convention:

```yaml
- rule_id: python.<category>.<kebab-name>
  invariant: one-sentence, imperative, transferable phrasing
  evidence:
    - file: <relative path>
      line: <int>
      excerpt: <≤120 chars of the exact line>
  adoption: "<high|mixed|low>"
  rationale: why this convention matters (1 sentence)
  enforceability: "ast|regex|teach-only"
  org_specific: true|false   # true if tied to this codebase's domain
```

## Rules of honesty (violations are rejected)

1. Every proposed convention MUST have ≥3 evidence lines with real
   file:line citations from the files you were given. No citations = no rule.
2. Do not propose universal Python best practices as "discovered" — we
   already own those. Propose what is SPECIFIC to how this codebase does
   things (its async style, its settings/config pattern, its exception
   hierarchy, its API response shapes).
3. `adoption: high` = followed consistently (>80%); `low` = consistently
   violated (fix-magnet); `mixed` = inconsistent.
4. Flag org_specific conventions honestly — valuable to the buyer but must
   be labeled.
5. Never invent files or lines. If you cannot cite, skip the convention.

## Output

Only the YAML block. No preamble, no commentary.
