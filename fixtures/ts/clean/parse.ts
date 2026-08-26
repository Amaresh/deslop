export function read(raw: string) {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}
