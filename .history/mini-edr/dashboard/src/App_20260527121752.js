import { useEffect, useState } from "react";
import axios from "axios";

import "./styles.css";

function App() {

  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState("");

  useEffect(() => {

    fetchTelemetry();

    const interval = setInterval(() => {
      fetchTelemetry();
    }, 4000);

    return () => clearInterval(interval);

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

      {/* SIDEBAR */}

      <div className="sidebar">

        <div className="sidebar-top">

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
              Detections
            </div>

            <div className="menu-item">
              MITRE
            </div>

          </div>

        </div>

        <div className="sidebar-footer">

          <div className="agent-status">

            <div className="status-dot"></div>

            Agent Connected

          </div>

        </div>

      </div>

      {/* MAIN */}

      <div className="main">

        {/* HEADER */}

        <div className="header">

          <div>

            <h1>
              Threat Monitoring Dashboard
            </h1>

            <p>
              Endpoint Detection & Response Platform
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

        {/* OVERVIEW */}

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
              1
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

        {/* CONTENT */}

        <div className="content-grid">

          {/* ALERT PANEL */}

          <div className="panel alerts-panel">

            <div className="panel-header">
              Live Threat Alerts
            </div>

            <div className="alerts-list">

              {alerts
                .slice()
                .reverse()
                .slice(0, 8)
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

          {/* TELEMETRY */}

          <div className="panel telemetry-panel">

            <div className="panel-header">
              Live Telemetry Stream
            </div>

            <div className="telemetry-scroll">

              <table>

                <thead>

                  <tr>

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