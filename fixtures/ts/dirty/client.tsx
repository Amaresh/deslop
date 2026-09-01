'use client'
import { readFileSync } from "node:fs"

export function Page() {
  return <pre>{readFileSync("/etc/hosts", "utf8")}</pre>
}
