import { useState } from "react"
export function EmailForm() {
  const [email, setEmail] = useState("")
  return <input value={email} onChange={(e) => setEmail(e.target.value)} />
}
