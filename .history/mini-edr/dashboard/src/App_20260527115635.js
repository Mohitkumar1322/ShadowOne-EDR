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
    }, 5000);

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

  const filteredEvents = events.filter((event) =>
    event.process_name
      ?.toLowerCase()
      .includes(search.toLowerCase())
  );

  const alertCount = events.filter(
    (event) => event.alert
  ).length;

  return (

    <div className="app">

      {/* SIDEBAR */}

      <div className="sidebar">

        <div className="logo">
          Mini EDR
        </div>

        <div className="sidebar-menu">

          <div className="sidebar-item">
            Dashboard
          </div>

          <div className="sidebar-item">
            Telemetry
          </div>

          <div className="sidebar-item">
            Alerts
          </div>

          <div className="sidebar-item">
            Hosts
          </div>

        </div>

      </div>

      {/* MAIN */}

      <div className="main">

        {/* TOPBAR */}

        <div className="topbar">

          <div className="dashboard-title">

            <h1>
              Security Dashboard
            </h1>

            <p>
              Endpoint Detection & Response
            </p>

          </div>

          <input
            type="text"
            placeholder="Search Process..."
            className="search-box"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />

        </div>

        {/* STATS */}

        <div className="stats-grid">

          <div className="stat-card">

            <div className="stat-title">
              Total Events
            </div>

            <div className="stat-value">
              {events.length}
            </div>

          </div>

          <div className="stat-card">

            <div className="stat-title">
              Alerts
            </div>

            <div
              className="stat-value"
              style={{ color: "#f87171" }}
            >
              {alertCount}
            </div>

          </div>

          <div className="stat-card">

            <div className="stat-title">
              Hosts
            </div>

            <div className="stat-value">
              1
            </div>

          </div>

          <div className="stat-card">

            <div className="stat-title">
              Threat Level
            </div>

            <div
              className="stat-value"
              style={{ color: "#facc15" }}
            >
              Medium
            </div>

          </div>

        </div>

        {/* TABLE */}

        <div className="table-container">

          <div className="table-header">
            Live Telemetry
          </div>

          <div className="table-scroll">

            <table>

              <thead>

                <tr>

                  <th>Process</th>
                  <th>PID</th>
                  <th>Command</th>
                  <th>Status</th>
                  <th>Severity</th>
<th>MITRE</th>
                  <th>Parent</th>

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
                      {event.pid}
                    </td>

                    <td className="command">
                      {event.cmdline}
                    </td>

                    <td>


                      {event.alert ? (

                        <span className="alert">
                          ALERT
                        </span>

                      ) : (

                        <span className="safe">
                          SAFE
                        </span>

                      )}

                    </td>
                    <td>{event.parent_process}</td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      </div>

    </div>
  );
}

export default App;