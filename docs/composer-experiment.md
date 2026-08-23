# The composer experiment: does reading a rule change what an agent writes?

**Date:** 2026-08-15 · **Model:** Composer (one model, one task) · **n=1 per arm**

This is the evidence behind `no-jpql-null-or-lower` being the first
`checker`-verified rule. It is a single controlled comparison — evidence that
the teach mechanism works when the rule is loaded, not a general guarantee
across models or harnesses.

## Setup

Two isolated sessions. Identical task: write a Spring Data JPQL optional
status filter on `CustomerRepository`.

- **Control:** no skill file provided.
- **Treatment:** instructed to read `skills/no-jpql-null-or-lower/SKILL.md`
  first. Invariant: avoid `:param IS NULL OR` combined with `LOWER` on
  optional filters; use an empty-string sentinel (`:param = ''`) for "no
  filter" instead.

## Control output

```sql
SELECT c FROM Customer c WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))
```

The agent wrote the classic anti-pattern: `:status IS NULL OR` makes the
predicate true for every row when the caller passes `null`, so no filter is
applied at all. The agent even explained this behavior in its summary — and
wrote it anyway.

## Treatment output

```sql
SELECT c FROM Customer c WHERE :status = '' OR LOWER(c.status) = LOWER(:status)
```

The agent read the skill, restated the invariant, and wrote the empty-string
sentinel form.

## What we conclude

- A skill file changed what the model wrote **when the model read it**.
- This is one rule, one model, one task per arm. It justifies verifying a
  detector against agent-written samples; it does not justify claiming every
  rule steers every agent.

## Why the checker exists anyway

Prevention is unreliable: agents may not load the skill, and compliance varies
by model. `scripts/check.py` deterministically gates the patterns we can prove
agents emit (concatenated queries, text blocks, same-file and cross-file
constant concatenation all fail the JPQL detector). Steer first; gate what
slips through.
