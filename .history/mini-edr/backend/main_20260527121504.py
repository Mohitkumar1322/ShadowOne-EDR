from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
import socketio
import uvicorn

# SOCKET SERVER

sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*'
)

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


def detect_suspicious(process, parent, cmdline):

    process = process.lower()
    parent = parent.lower()
    cmdline = cmdline.lower()

    # Encoded PowerShell
    if "powershell" in process and "-enc" in cmdline:

        return {
            "alert": "Encoded PowerShell",
            "severity": "high",
            "mitre": "T1059.001"
        }

    # Office spawning CMD
    if "winword.exe" in parent and "cmd.exe" in process:

        return {
            "alert": "Office Spawned CMD",
            "severity": "critical",
            "mitre": "T1204"
        }

    # CMD spawning PowerShell
    if "cmd.exe" in parent and "powershell.exe" in process:

        return {
            "alert": "CMD Spawned PowerShell",
            "severity": "medium",
            "mitre": "T1059"
        }

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

    detection = detect_suspicious(

        data.get("process_name", ""),
        data.get("parent_process", ""),
        data.get("cmdline", "")

    )

    if detection:

        data["alert"] = detection["alert"]

        data["severity"] = detection["severity"]

        data["mitre"] = detection["mitre"]

    collection.insert_one(data)

    return {"status": "received"}