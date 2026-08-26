export async function load(id: string) {
  return fetch("/items/" + id, { signal: AbortSignal.timeout(5_000) })
}
