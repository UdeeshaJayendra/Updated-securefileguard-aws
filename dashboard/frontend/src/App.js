import { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import "./App.css";

const API_URL =
  "https://bi2i6zv4kg.execute-api.ap-south-1.amazonaws.com";

function App() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const [statsResponse, scansResponse] = await Promise.all([
        fetch(`${API_URL}/statistics`),
        fetch(`${API_URL}/scans`),
      ]);

      if (!statsResponse.ok || !scansResponse.ok) {
        throw new Error("Failed to fetch dashboard data");
      }

      const statsData = await statsResponse.json();
      const scansData = await scansResponse.json();

      setStats(statsData);
      setScans(scansData);
    } catch (err) {
      console.error(err);
      setError("Unable to connect to SecureFileGuard API.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const chartData = stats
    ? [
        { name: "Clean", value: stats.clean },
        { name: "Suspicious", value: stats.suspicious },
        { name: "Quarantined", value: stats.quarantined },
      ]
    : [];

  if (loading) {
    return (
      <div className="loading">
        <h2>SecureFileGuard</h2>
        <p>Loading security data...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="header">
        <div>
          <h1>SecureFileGuard</h1>
          <p>Serverless File Security & Threat Detection</p>
        </div>

        <button onClick={loadDashboard}>Refresh</button>
      </header>

      {error && <div className="error">{error}</div>}

      {stats && (
        <>
          <section className="cards">
            <div className="card">
              <span>Total Files</span>
              <strong>{stats.total_files}</strong>
            </div>

            <div className="card clean">
              <span>Clean</span>
              <strong>{stats.clean}</strong>
            </div>

            <div className="card suspicious">
              <span>Suspicious</span>
              <strong>{stats.suspicious}</strong>
            </div>

            <div className="card quarantine">
              <span>Quarantined</span>
              <strong>{stats.quarantined}</strong>
            </div>

            <div className="card">
              <span>Avg Threat Score</span>
              <strong>{stats.average_threat_score}</strong>
            </div>
          </section>

          <section className="content-grid">
            <div className="panel chart-panel">
              <h2>Threat Distribution</h2>

              <div className="chart">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={chartData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                     label={({ name, percent }) =>
                     `${name} ${(percent * 100).toFixed(1)}%`
                     }
                    >
                      {chartData.map((entry, index) => (
                    <Cell
                      key={entry.name}
                      fill={["#22c55e", "#f59e0b", "#ef4444"][index]}
                     />
                    ))}
                    </Pie>

                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel">
              <h2>Security Overview</h2>

              <div className="overview">
                <div>
                  <span>Detection Rate</span>
                  <strong>
                    {stats.total_files > 0
                      ? (
                          ((stats.suspicious + stats.quarantined) /
                            stats.total_files) *
                          100
                        ).toFixed(1)
                      : 0}
                    %
                  </strong>
                </div>

                <div>
                  <span>Quarantine Rate</span>
                  <strong>
                    {stats.total_files > 0
                      ? (
                          (stats.quarantined / stats.total_files) *
                          100
                        ).toFixed(1)
                      : 0}
                    %
                  </strong>
                </div>

                <div>
                  <span>System Status</span>
                  <strong className="online">ONLINE</strong>
                </div>
              </div>
            </div>
          </section>

          <section className="panel scans-panel">
            <div className="table-header">
              <h2>Recent Scans</h2>
              <span>{scans.length} scan records</span>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Status</th>
                    <th>Threat Score</th>
                    <th>SHA-256</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {scans.map((scan, index) => (
                    <tr key={scan.scan_id || index}>
                      <td>{scan.file_name || "Unknown"}</td>

                      <td>
                        <span
                          className={`status ${String(
                            scan.status || ""
                          ).toLowerCase()}`}
                        >
                          {scan.status}
                        </span>
                      </td>

                      <td>
                        <strong>{scan.threat_score ?? 0}</strong>
                      </td>

                      <td className="hash">
                        {scan.sha256
                          ? `${scan.sha256.substring(0, 16)}...`
                          : "-"}
                      </td>

                      <td>
                        {scan.timestamp
                          ? new Date(scan.timestamp).toLocaleString()
                          : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

export default App;