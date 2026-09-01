---
name: stopthatslop-go
description: >-
  Go HTTP and database/sql pack. Use when editing Go net/http handlers,
  websocket upgraders, or database/sql Scan/Query. One pack, several
  invariants. Apply only the section that matches the files in scope.
disable-model-invocation: false
paths: '**/*.go'
license: MIT
metadata:
  pack: stopthatslop-go-v1
  kind: pack-index
---

# stopthatslop-go

Do not apply every section. Match the file in front of you.

CI gates all eight rules (`enforcement: checker`). Needs a Go toolchain
so `stopthatslop check` can build the AST helper.

## HTTP handlers

Do not run SQL, outbound `http.Get`, `context.Background()`, or a detached
`go` statement from the handler. Inject a store/client and use `r.Context()`.

## Secrets

Compare request secrets with `crypto/subtle`, never `==`.

## SQL

Bound parameters, not `fmt.Sprintf`. Scan nullable / outer-join columns into
`sql.Null*` or pointers.

## Websockets

`websocket.Upgrader.CheckOrigin` must not always return `true`.
