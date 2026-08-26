export async function format(value: unknown) {
  const { default: pick } = await import("lodash/pick.js")
  return pick(value, ["id"])
}
