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
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.react.no-mixed-controlled-uncontrolled
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
<input value={email} defaultValue="" onChange={(e) => setEmail(e.target.value)} />
```

Do not set both `value` and `defaultValue` (or `checked` and `defaultChecked`)
on the same node. Pick one. A `value` without `onChange` is also a frozen
field; CI flags the both-props case.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.react.no-mixed-controlled-uncontrolled
```
