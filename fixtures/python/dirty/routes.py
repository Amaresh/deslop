import requests
from fastapi import FastAPI
app = FastAPI()

@app.get("/stock/{sku}")
async def catalog_stock(sku: str):
    return requests.get(f"https://x/{sku}").json()
