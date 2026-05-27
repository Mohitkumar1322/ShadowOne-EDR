import { useEffect, useState } from "react";
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