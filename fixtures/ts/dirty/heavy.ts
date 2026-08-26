import pick from "lodash/pick.js"
export function format(value: unknown) {
  return pick(value, ["id"])
}
