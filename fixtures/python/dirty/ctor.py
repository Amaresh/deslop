from fastapi import FastAPI
import httpx
app = FastAPI()

@app.get("/stock")
async def stock():
    async with httpx.AsyncClient(timeout=5) as client:
        return (await client.get("https://x")).json()
