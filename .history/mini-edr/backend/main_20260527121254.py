from fastapi import FastAPI

    # Encoded PowerShell
    if "powershell" in process and "-enc" in cmdline:

        return {
            "alert": "Encoded PowerShell",
            "severity": "high",
            "mitre": "T1059.001"
        }

    # Office spawning cmd
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

# ROUTES

@app.get("/")
def home():
    return {"message": "Mini EDR Running"}

@app.get("/telemetry")
def get_telemetry():

    data = list(
        collection.find({}, {"_id": 0})
    )

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

    # REALTIME EMIT

    await sio.emit("new_event", data)

    return {"status": "received"}

# SOCKET APP

socket_app = socketio.ASGIApp(
    sio,
    app
)

if __name__ == "__main__":
    uvicorn.run(socket_app, host="0.0.0.0", port=8000)