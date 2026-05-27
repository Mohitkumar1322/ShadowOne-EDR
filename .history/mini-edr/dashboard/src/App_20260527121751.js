# Mini EDR — Next Phase Upgrade

This phase upgrades your project from:

```text
basic telemetry dashboard
```

into:

```text
real-time multi-host EDR platform
```

We will implement:

1. Multi-host support
2. Realtime telemetry using WebSockets
3. Better backend architecture
4. Alert filtering
5. Live event streaming

---

# PROJECT STRUCTURE

## Backend

```text
backend/
 ├── main.py
 ├── requirements.txt
```

## Agent

```text
agent/
 ├── agent.py
```

## Frontend

```text
dashboard/src/
 ├── App.js
 ├── styles.css
```

---

# STEP 1 — INSTALL BACKEND DEPENDENCIES

Inside backend:

```bash
pip install fastapi uvicorn pymongo python-socketio
```

---

# STEP 2 — REPLACE ENTIRE backend/main.py

```python
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

# DATABASE

client = MongoClient("mongodb://localhost:27017/")
db = client["mini_edr"]
collection = db["telemetry"]

# DETECTION ENGINE

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
```

---

# STEP 3 — REPLACE ENTIRE agent/agent.py

```python
import psutil
import requests
import socket
import time

BACKEND_URL = "http://127.0.0.1:8000/telemetry"

hostname = socket.gethostname()

while True:

    for proc in psutil.process_iter([
        'pid',
        'name',
        'cmdline'
    ]):

        try:

            parent_pid = proc.ppid()

            try:
                parent_name = psutil.Process(parent_pid).name()
            except:
                parent_name = "Unknown"

            telemetry = {

                "hostname": hostname,

                "pid": proc.info['pid'],

                "ppid": parent_pid,

                "process_name": proc.info['name'],

                "parent_process": parent_name,

                "cmdline": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            }

            requests.post(
                BACKEND_URL,
                json=telemetry
            )

            print(telemetry)

        except Exception as e:
            print(e)

    time.sleep(5)
```

---

# STEP 4 — INSTALL FRONTEND DEPENDENCIES

Inside dashboard:

```bash
npm install axios socket.io-client
```

---

# STEP 5 — REPLACE ENTIRE dashboard/src/App.js

```javascript
import { useEffect, useState } from "react";
import axios from "axios";
import { io } from "socket.io-client";

import "./styles.css";

const socket = io("http://127.0.0.1:8000");

function App() {

  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState("");

  useEffect(() => {

    fetchTelemetry();

    socket.on("new_event", (event) => {

      setEvents((prev) => [...prev, event]);

    });

    return () => {
      socket.off("new_event");
    };

  }, []);

  const fetchTelemetry = async () => {

    try {

      const response = await axios.get(
        "http://127.0.0.1:8000/telemetry"
      );

      setEvents(response.data);

    } catch (error) {

      console.log(error);

    }
  };

  const alerts = events.filter(
    (event) => event.alert
  );

  const hosts = [...new Set(events.map(
    e => e.hostname
  ))];

  const filteredEvents = events.filter((event) =>
    event.process_name
      ?.toLowerCase()
      .includes(search.toLowerCase())
  );

  const getSeverityClass = (severity) => {

    if (severity === "critical") return "critical";
    if (severity === "high") return "high";
    if (severity === "medium") return "medium";

    return "safe";
  };

  return (

    <div className="dashboard">

      <div className="sidebar">

        <div>

          <div className="brand">

            <div className="brand-logo">
              E
            </div>

            <div>

              <h2>Mini EDR</h2>

              <p>Security Console</p>

            </div>

          </div>

          <div className="menu">

            <div className="menu-item active">
              Dashboard
            </div>

            <div className="menu-item">
              Telemetry
            </div>

            <div className="menu-item">
              Threats
            </div>

            <div className="menu-item">
              Hosts
            </div>

            <div className="menu-item">
              MITRE
            </div>

          </div>

        </div>

        <div className="agent-status">

          <div className="status-dot"></div>

          Agent Connected

        </div>

      </div>

      <div className="main">

        <div className="header">

          <div>

            <h1>
              Threat Monitoring Dashboard
            </h1>

            <p>
              Realtime Endpoint Detection Platform
            </p>

          </div>

          <input
            type="text"
            placeholder="Search process..."
            value={search}
            className="search"
            onChange={(e) => setSearch(e.target.value)}
          />

        </div>

        <div className="overview-grid">

          <div className="overview-card">

            <div className="overview-title">
              Total Events
            </div>

            <div className="overview-value">
              {events.length}
            </div>

          </div>

          <div className="overview-card alert-glow">

            <div className="overview-title">
              Threat Alerts
            </div>

            <div className="overview-value red">
              {alerts.length}
            </div>

          </div>

          <div className="overview-card">

            <div className="overview-title">
              Connected Hosts
            </div>

            <div className="overview-value">
              {hosts.length}
            </div>

          </div>

          <div className="overview-card">

            <div className="overview-title">
              Threat Level
            </div>

            <div className="overview-value yellow">
              Medium
            </div>

          </div>

        </div>

        <div className="content-grid">

          <div className="panel alerts-panel">

            <div className="panel-header">
              Live Threat Alerts
            </div>

            <div className="alerts-list">

              {alerts
                .slice()
                .reverse()
                .slice(0, 10)
                .map((alert, index) => (

                <div
                  key={index}
                  className={`threat-card ${getSeverityClass(alert.severity)}`}
                >

                  <div className="threat-top">

                    <div className="threat-name">
                      {alert.alert}
                    </div>

                    <div className={`severity-badge ${getSeverityClass(alert.severity)}`}>
                      {alert.severity}
                    </div>

                  </div>

                  <div className="threat-info">

                    <div>
                      <strong>Host:</strong>
                      {" "}
                      {alert.hostname}
                    </div>

                    <div>
                      <strong>Process:</strong>
                      {" "}
                      {alert.process_name}
                    </div>

                    <div>
                      <strong>Parent:</strong>
                      {" "}
                      {alert.parent_process}
                    </div>

                    <div>
                      <strong>MITRE:</strong>
                      {" "}
                      {alert.mitre}
                    </div>

                  </div>

                </div>

              ))}

            </div>

          </div>

          <div className="panel telemetry-panel">

            <div className="panel-header">
              Live Telemetry Stream
            </div>

            <div className="telemetry-scroll">

              <table>

                <thead>

                  <tr>

                    <th>Host</th>
                    <th>Process</th>
                    <th>Parent</th>
                    <th>PID</th>
                    <th>Status</th>

                  </tr>

                </thead>

                <tbody>

                  {filteredEvents
                    .slice()
                    .reverse()
                    .map((event, index) => (

                    <tr key={index}>

                      <td>
                        {event.hostname}
                      </td>

                      <td>
                        {event.process_name}
                      </td>

                      <td>
                        {event.parent_process}
                      </td>

                      <td>
                        {event.pid}
                      </td>

                      <td>

                        {event.alert ? (

                          <span className={`severity-badge ${getSeverityClass(event.severity)}`}>
                            ALERT
                          </span>

                        ) : (

                          <span className="safe-badge">
                            SAFE
                          </span>

                        )}

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </div>

        </div>

      </div>

    </div>

  );
}

export default App;
```

---

# STEP 6 — KEEP EXISTING styles.css

Your current styles.css already works well.

---

# STEP 7 — RUN EVERYTHING

## Backend

```bash
python main.py
```

## Agent

```bash
python agent.py
```

## Frontend

```bash
npm start
```

---

# WHAT YOU JUST ADDED

You now have:

✅ Multi-host telemetry
✅ WebSocket realtime streaming
✅ Live alerts
✅ Realtime event injection
✅ Better EDR architecture
✅ Host tracking
✅ SOC-like telemetry flow

This is now MUCH closer to:

```text
actual detection engineering platform
```

than a college dashboard.

---

# NEXT FEATURES AFTER THIS

We will next implement:

1. Process Tree Visualization
2. Network Monitoring
3. Persistence Detection
4. Sigma Rules
5. PowerShell Logging
6. File Integrity Monitoring
7. Threat Hunting Search
