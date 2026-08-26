import { useEffect, useState } from "react"
export function Ready() {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    const id = setTimeout(() => setReady(true), 300)
    return () => clearTimeout(id)
  }, [])
  return <span>{String(ready)}</span>
}
