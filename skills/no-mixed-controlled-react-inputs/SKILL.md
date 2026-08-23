---
name: no-mixed-controlled-react-inputs
description: >-
  Do not give a React input a value prop without an onChange (or vice versa).
  Every controlled input needs both; uncontrolled inputs need defaultValue and
  a ref. Use only when editing React JSX form elements. Do not use for
  non-React frameworks, custom components that manage this internally, or
  file inputs (always uncontrolled).
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-ts-node-v1
  engine_rule_id: typescript.react.no-mixed-controlled-uncontrolled-inputs
  globs: "**/*.tsx"
---

# No mixed controlled/uncontrolled inputs

`<input value={state} />` without `onChange` renders a read-only field the
user cannot type into; switching `value` to `defaultValue` on a later edit
flips it to uncontrolled and React logs the warning every agent ignores.

## Do

```tsx
function EmailForm() {
  const [email, setEmail] = useState("");

  return (
    <input
      value={email}
      onChange={(event) => setEmail(event.target.value)}
      placeholder="you@example.com"
    />
  );
}
```

Or deliberately uncontrolled:

```tsx
const emailRef = useRef<HTMLInputElement>(null);

<form onSubmit={() => submit(emailRef.current?.value ?? "")}>
  <input ref={emailRef} defaultValue="" name="email" />
</form>
```

## Do not

```tsx
<input value={email} placeholder="you@example.com" /> {/* frozen field */}
<input defaultValue={email} onChange={(e) => setEmail(e.target.value)} />
{/* mixing both worlds; value drifts from state */}
```

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
