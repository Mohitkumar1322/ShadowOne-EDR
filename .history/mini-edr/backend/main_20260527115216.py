from fastapi import FastAPI
from pymongo import MongoClient
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient("mongodb://localhost:27017/")
db = client["mini_edr"]
collection = db["telemetry"]


def detect_suspicious(cmdline):

    if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
        return "Encoded PowerShell Detected"

    return None


@app.get("/")
def home():
    return {"message": "Mini EDR Backend Running"}


@app.get("/telemetry")

def get_telemetry():

    data = list(collection.find({}, {"_id": 0}))

    return data


@app.post("/telemetry")
async def receive_telemetry(data: dict):

    # Detection logic
    alert = detect_suspicious(data.get("cmdline", ""))

    if alert:
        data["alert"] = alert

    collection.insert_one(data)

    return {"status": "received"}