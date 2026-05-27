import { useEffect, useState } from "react";
import axios from "axios";

function App() {

  const [events, setEvents] = useState([]);

  useEffect(() => {

    fetchTelemetry();

    const interval = setInterval(() => {
      fetchTelemetry();
    }, 5000);

    return () => clearInterval(interval);

  }, []);

  const fetchTelemetry = async () => {

    try {

      const response = await axios.get("http://127.0.0.1:8000/telemetry");

      setEvents(response.data);

    } catch (error) {

      console.log(error);

    }
  };

  return (

    <div style={{ padding: "20px", fontFamily: "Arial" }}>

      <h1>Mini EDR Dashboard</h1>

      <h3>Total Events: {events.length}</h3>

      {events.slice().reverse().map((event, index) => (

        <div
          key={index}
          style={{
            border: "1px solid gray",
            padding: "10px",
            marginBottom: "10px",
            borderRadius: "10px"
          }}
        >

          <p><strong>Process:</strong> {event.process_name}</p>

          <p><strong>PID:</strong> {event.pid}</p>

          <p><strong>Command:</strong> {event.cmdline}</p>

          {event.alert && (

            <p style={{ color: "red" }}>
              <strong>ALERT:</strong> {event.alert}
            </p>

          )}

        </div>

      ))}

    </div>
  );
}

export default App;