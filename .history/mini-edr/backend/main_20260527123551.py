from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

import socketio
import uvicorn

# =========================
# SOCKET.IO SERVER
# =========================

sio = socketio.AsyncServer(

    async_mode="asgi",

    cors_allowed_origins="*"

)

# =========================
# FASTAPI APP
# =========================

fastapi_app = FastAPI()

fastapi_app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]

)

# =========================
# DATABASE
# =========================

client = MongoClient(
    "mongodb://localhost:27017/"
)

db = client["mini_edr"]

collection = db["telemetry"]

# =========================
# DETECTION ENGINE
# =========================

def detect_suspicious(process, parent, cmdline):

    process = process.lower()

    parent = parent.lower()

    cmdline = cmdline.lower()

    # -------------------------
    # Encoded PowerShell
    # -------------------------

    if "powershell" in process and "-enc" in cmdline:

        return {

            "alert": "Encoded PowerShell",

            "severity": "high",

            "mitre": "T1059.001"

        }

    # -------------------------
    # Office spawning CMD
    # -------------------------

    if "winword.exe" in parent and "cmd.exe" in process:

        return {

            "alert": "Office Spawned CMD",

            "severity": "critical",

            "mitre": "T1204"

        }

    # -------------------------
    # CMD spawning PowerShell
    # -------------------------

    if "cmd.exe" in parent and "powershell.exe" in process:

        return {

            "alert": "CMD Spawned PowerShell",

            "severity": "medium",

            "mitre": "T1059"

        }

    # -------------------------
    # Suspicious LOLBins
    # -------------------------

    lolbins = [

        "certutil.exe",

        "mshta.exe",

        "rundll32.exe",

        "regsvr32.exe"

    ]

    if process in lolbins:

        return {

            "alert": "Suspicious LOLBin Execution",

            "severity": "high",

            "mitre": "T1218"

        }

    return None

# =========================
# THREAT SCORE ENGINE
# =========================

def calculate_threat_score(data):

    score = 0

    if data.get("severity") == "critical":
        score += 100

    elif data.get("severity") == "high":
        score += 70

    elif data.get("severity") == "medium":
        score += 40

    process = data.get("process_name", "").lower()

    if "powershell" in process:
        score += 20

    if "cmd.exe" in process:
        score += 10

    return score

# =========================
# ROUTES
# =========================

@fastapi_app.get("/")
def home():

    return {

        "message": "Mini EDR Running"

    }

# -------------------------
# GET TELEMETRY
# -------------------------

@fastapi_app.get("/telemetry")
def get_telemetry():

    data = list(

        collection.find({}, {"_id": 0})

    )

    return data

# -------------------------
# RECEIVE TELEMETRY
# -------------------------

@fastapi_app.post("/telemetry")
async def receive_telemetry(data: dict):

    detection = detect_suspicious(

        data.get("process_name", ""),

        data.get("parent_process", ""),

        data.get("cmdline", "")

    )

    # =========================
    # APPLY DETECTIONS
    # =========================

    if detection:

        data["alert"] = detection["alert"]

        data["severity"] = detection["severity"]

        data["mitre"] = detection["mitre"]

    # =========================
    # THREAT SCORE
    # =========================

    data["threat_score"] = calculate_threat_score(data)

    # =========================
    # STORE CLEAN COPY
    # =========================

    collection.insert_one(data.copy())

    # =========================
    # REALTIME EVENT STREAM
    # =========================

    await sio.emit(

        "new_event",

        data

    )

    return {

        "status": "received"

    }

# =========================
# SOCKET.IO + FASTAPI APP
# =========================

app = socketio.ASGIApp(

    sio,

    fastapi_app

)

# =========================
# MAIN
# =========================

if __name__ == "__main__":

    uvicorn.run(

        app,

        host="0.0.0.0",

        port=8000

    )