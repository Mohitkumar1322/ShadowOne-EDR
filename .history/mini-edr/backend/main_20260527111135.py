from fastapi import FastAPI
from pymongo import MongoClient

app = FastAPI()

client = MongoClient("mongodb://localhost:27017/")
db = client["mini_edr"]
collection = db["telemetry"]

@app.get("/")
def home():
    return {"message": "Mini EDR Backend Running"}

@app.post("/telemetry")
async def receive_telemetry(data: dict):
    collection.insert_one(data)
    return {"status": "received"}