export async function mixed(fetch: typeof globalThis.fetch, url: string, init: RequestInit) {
  await fetch(url)
  await globalThis.fetch(url, { signal: AbortSignal.timeout(1) })
  await window.fetch(url, init)
}
