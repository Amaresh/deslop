#!/usr/bin/env python3
"""Smoke checks: run goast-facts over each testdata file and assert key facts.

Usage: python3 smoke_check.py
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE / "goast-facts"

failures = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if not cond and detail else ""))
    if not cond:
        failures.append(label)


def facts_for(name):
    p = subprocess.run(
        [str(BIN), str(HERE / "testdata" / name)],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 0, f"goast-facts failed on {name}: {p.stderr}"
    return json.loads(p.stdout)


def fn_with_cmp(facts, pred):
    return any(pred(c) for f in facts["functions"] for c in f["string_comparisons"])


def call(facts, suffix):
    return [c for f in facts["functions"] for c in f["calls"] if c["name"].endswith(suffix)]


# ---- 1. secret_compare.go ----
f1 = facts_for("secret_compare.go")
check("secret: imports crypto/subtle", "crypto/subtle" in f1["imports"])
check("secret: subtle.ConstantTimeCompare call captured",
      len(call(f1, "subtle.ConstantTimeCompare")) == 1)
check("secret: presence check `token != \"\"` is a != comparison with literal operand",
      fn_with_cmp(f1, lambda c: c["op"] == "==" and 'literal ""' in c["operands"]))
check("secret: plain value comparison `token != expectedToken` between identifiers",
      fn_with_cmp(f1, lambda c: c["op"] == "!="
                  and "identifier token" in c["operands"]
                  and "identifier expectedToken" in c["operands"]))
check("secret: strings.EqualFold recorded as EqualFold comparison",
      fn_with_cmp(f1, lambda c: c["op"] == "EqualFold"))
# multi-comparison line: `q != "" && q != tokenOf(r)` -> two entries, same line
lines_30 = [c for f in f1["functions"] for c in f["string_comparisons"] if c["line"] == 30]
check("secret: multi-comparison line yields two distinct comparisons", len(lines_30) == 2)
header_gets = [c for f in f1["functions"] for c in f["string_comparisons"]
               if c["op"] == "==" and any(o.startswith("selector r.Header.Get") for o in c["operands"])
               or c["op"] == "==" and any(o.startswith("call r.Header.Get") for o in c["operands"])]
check("secret: header-token comparison captures selector/call operand text", len(header_gets) >= 1)

# ---- 2. websocket_origin.go ----
f2 = facts_for("websocket_origin.go")
ups = [c for c in f2["composite_literals"] if c["type"] == "websocket.Upgrader"]
check("ws: two websocket.Upgrader composite literals found", len(ups) == 2)
inline = next((u for u in ups if u["fields_detailed"].get("CheckOrigin", {}).get("kind") == "func_literal"), None)
ref = next((u for u in ups if u["fields_detailed"].get("CheckOrigin", {}).get("kind") == "func_ref"), None)
check("ws: inline CheckOrigin func-literal with body line range",
      inline is not None
      and inline["fields"]["CheckOrigin"] == f"func-literal lines {inline['fields_detailed']['CheckOrigin']['lines'][0]}-{inline['fields_detailed']['CheckOrigin']['lines'][1]}")
check("ws: func_ref CheckOrigin resolves to isValidOrigin",
      ref is not None and ref["fields_detailed"]["CheckOrigin"]["ref_name"] == "isValidOrigin")
check("ws: resolved helper known to return literal true",
      ref is not None and ref["fields_detailed"]["CheckOrigin"]["returns_literal_bool"] is True
      and ref["fields_detailed"]["CheckOrigin"]["always_returns_true"] is True)
idx = f2["named_funcs_index"]
check("ws: named_funcs_index[isValidOrigin] returns_literal_bool=true",
      idx.get("isValidOrigin", {}).get("returns_literal_bool") is True)
strict = idx.get("strictOrigin", {})
check("ws: strictOrigin (value comparison body) NOT flagged as literal-bool/always-true",
      strict.get("returns_literal_bool") is False and strict.get("always_returns_true") is False)

# ---- 3. nullable_scan.go ----
f3 = facts_for("nullable_scan.go")
queries = call(f3, "db.Query")
check("sql: db.Query captured with LEFT JOIN in query text",
      queries and "LEFT JOIN" in queries[0]["args_summary"][0])
scans = call(f3, "rows.Scan")
check("sql: rows.Scan(&id, &bikeID) args visible",
      scans and scans[0]["args_summary"] == ["&id", "&bikeID"])
decls = {tuple(d["names"]): d for f in f3["functions"] for d in f["grouped_var_decls"]}
check("sql: grouped var decl for id+bikeID (parenthesized block)",
      decls.get(("id",), {}).get("grouped") is True
      and decls.get(("bikeID",), {}).get("grouped") is True)
check("sql: avatarURL separately declared as non-grouped string var",
      decls.get(("avatarURL",), {}).get("grouped") is False
      and decls.get(("avatarURL",), {}).get("type") == "string")
qrow_scans = [c for f in f3["functions"] for c in f["calls"]
              if c["name"].endswith(".Scan") and "&avatarURL" in c["args_summary"]]
check("sql: QueryRow().Scan(&avatarURL) chain ties Scan to its query",
      qrow_scans and "SELECT avatar_url" in qrow_scans[0]["name"])
bio_scans = [c for f in f3["functions"] for c in f["calls"]
             if c["name"].endswith(".Scan") and "&bio" in c["args_summary"]]
check("sql: sql.NullString scan into &bio with its own query",
      bio_scans and "SELECT bio" in bio_scans[0]["name"])
check("sql: bio declared as sql.NullString",
      decls.get(("bio",), {}).get("type") == "sql.NullString")

# ---- 4. go_stmt.go ----
f4 = facts_for("go_stmt.go")
serve = next(f for f in f4["functions"] if f["name"] == "ServeHTTP")
worker = next(f for f in f4["functions"] if f["name"] == "worker")
check("go: ServeHTTP records four go_stmts", len(serve["go_stmts"]) == 4)
audit = next((g for g in serve["go_stmts"] if "audit" in g["call_summary"]), None)
orphan = next((g for g in serve["go_stmts"] if "orphan" in g["call_summary"]), None)
done_lit = next((g for g in serve["go_stmts"] if ".Done()" in g["call_summary"]), None)
ctx_arg = next((g for g in serve["go_stmts"] if g["call_summary"].startswith("work(")), None)
check("go: go audit(r.Context()) has_context",
      audit is not None and audit["has_context"] is True)
check("go: go orphan() has_context false",
      orphan is not None and orphan["has_context"] is False)
check("go: func-lit with Context().Done() has_context",
      done_lit is not None and done_lit["has_context"] is True)
check("go: go work(ctx) has_context via ident ctx",
      ctx_arg is not None and ctx_arg["has_context"] is True)
check("go: worker (non-handler) still records go_stmts",
      len(worker["go_stmts"]) == 1
      and worker["go_stmts"][0]["has_context"] is False)
check("go: existing Call facts still captured on ServeHTTP",
      any(c["name"].endswith("audit") or c["name"].endswith("orphan")
          for c in serve["calls"]))

print()
if failures:
    print(f"{len(failures)} check(s) FAILED:")
    for fl in failures:
        print(f"  - {fl}")
    sys.exit(1)
print("all smoke checks passed")
