import { useEffect, useState } from "react"
export function Ready() {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    setTimeout(() => setReady(true), 300)
  }, [])
  return <span>{String(ready)}</span>
}
