import { useState } from "react"

export function EmailForm() {
  const [email, setEmail] = useState("")
  return <input value={email} defaultValue="" onChange={(e) => setEmail(e.target.value)} />
}
