import httpx
from fastapi import FastAPI, Request
app = FastAPI()

@app.get("/stock/{sku}")
async def catalog_stock(sku: str, client: httpx.AsyncClient):
    response = await client.get(f"https://x/{sku}", timeout=5.0)
    return response.json()
