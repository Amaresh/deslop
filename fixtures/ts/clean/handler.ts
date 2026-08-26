import express from "express"
const app = express()
app.get("/x", async (req, res) => {
  try {
    await req.json()
  } catch (err) {
    res.status(400).json({ error: "bad json" })
  }
})
