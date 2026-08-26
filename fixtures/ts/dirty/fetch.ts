export async function load(id: string) {
  return fetch("/items/" + id)
}
