export async function ingest(req: Request) {
  const raw = await req.text()
  JSON.parse(raw)
  try { JSON.parse(raw) } catch { JSON.parse(raw) }
  schema.parse(JSON.parse(raw))
  JSON.parse('{"a":1}')
  JSON.parse(JSON.stringify(raw))
  await request.json()
  res.json({ ok: true })
}
