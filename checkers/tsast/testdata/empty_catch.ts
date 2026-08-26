app.get("/x", async (req, res) => {
  try { await ping() } catch {}
  function decode(raw: string) {
    try { return JSON.parse(raw) } catch {}
  }
  res.json(decode("{}"))
})

export async function guard(ctx, next) {
  try { await next() } catch (e) { console.error(e) }
}
