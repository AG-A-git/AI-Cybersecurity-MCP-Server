import React, { useEffect, useState } from "react";
import DashboardCard from "../components/DashboardCard";
import { getDashboard } from "../services/api";

function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await getDashboard();

      console.log("Dashboard API response:", response);

      // getDashboard() already returns response.data
      setDashboard(response);

    } catch (err) {
      console.error("Failed to load dashboard:", err);

      if (err.response) {
        const detail = err.response.data?.detail;

        if (Array.isArray(detail)) {
          setError(
            detail.map((item) => item.msg).join(", ")
          );
        } else {
          setError(
            detail || "Failed to load dashboard data."
          );
        }
      } else {
        setError(
          "Cannot connect to backend. Make sure FastAPI is running."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  // -----------------------------------------
  // Loading
  // -----------------------------------------

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="mt-4">
          <h2>Loading Dashboard...</h2>
          <p>Please wait.</p>
        </div>
      </div>
    );
  }

  // -----------------------------------------
  // Error
  // -----------------------------------------

  if (error) {
    return (
      <div className="container-fluid">
        <div className="mt-4">
          <div className="alert alert-danger">
            <h5>Dashboard Error</h5>

            <p className="mb-2">
              {error}
            </p>

            <button
              className="btn btn-primary"
              onClick={loadDashboard}
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // -----------------------------------------
  // Safety check
  // -----------------------------------------

  if (!dashboard) {
    return (
      <div className="container-fluid">
        <div className="mt-4">
          <div className="alert alert-warning">
            No dashboard data available.
          </div>
        </div>
      </div>
    );
  }

  // -----------------------------------------
  // Dashboard
  // -----------------------------------------

  return (
    <div className="container-fluid">

      {/* Welcome */}
      <div className="mt-4 mb-4">
        <h2>
          Welcome, Security Analyst 👋
        </h2>

        <p>
          Monitor your vulnerability scans
          and security risks.
        </p>
      </div>

      {/* ============================= */}
      {/* Dashboard Cards */}
      {/* ============================= */}

      <div className="row">

        {/* Total Projects */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Total Projects"
            value={dashboard.total_projects ?? 0}
            icon="📁"
          />
        </div>

        {/* Total Scans */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Total Scans"
            value={dashboard.total_scans ?? 0}
            icon="🔍"
          />
        </div>

        {/* Critical */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Critical Vulnerabilities"
            value={
              dashboard.critical_vulnerabilities ?? 0
            }
            icon="🚨"
          />
        </div>

        {/* High */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="High Vulnerabilities"
            value={
              dashboard.high_vulnerabilities ?? 0
            }
            icon="⚠️"
          />
        </div>

      </div>

      {/* Medium + Low */}

      <div className="row">

        {/* Medium */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Medium Vulnerabilities"
            value={
              dashboard.medium_vulnerabilities ?? 0
            }
            icon="🟠"
          />
        </div>

        {/* Low */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Low Vulnerabilities"
            value={
              dashboard.low_vulnerabilities ?? 0
            }
            icon="🟢"
          />
        </div>

      </div>

      {/* ============================= */}
      {/* Recent Scans */}
      {/* ============================= */}

      <div className="card mt-4">

        <div className="card-header">
          <h5 className="mb-0">
            Recent Scans
          </h5>
        </div>

        <div className="card-body">

          <div className="table-responsive">

            <table className="table table-striped">

              <thead>
                <tr>
                  <th>Project</th>
                  <th>Date</th>
                  <th>Issues Found</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>

                {Array.isArray(dashboard.recent_scans) &&
                dashboard.recent_scans.length > 0 ? (
                  dashboard.recent_scans.map(
                    (scan, index) => (
                      <tr key={index}>

                        <td>
                          {scan.project}
                        </td>

                        <td>
                          {scan.date}
                        </td>

                        <td>
                          {scan.issues_found}
                        </td>

                        <td>
                          <span className="badge bg-success">
                            {scan.status}
                          </span>
                        </td>

                      </tr>
                    )
                  )
                ) : (
                  <tr>
                    <td
                      colSpan="4"
                      className="text-center"
                    >
                      No recent scans available.
                    </td>
                  </tr>
                )}

              </tbody>

            </table>

          </div>

        </div>

      </div>

      {/* ============================= */}
      {/* Vulnerability Trend */}
      {/* ============================= */}

      <div className="card mt-4 mb-4">

        <div className="card-body">

          <h5 className="mb-4">
            Vulnerability Trend
          </h5>

          <div className="table-responsive">

            <table className="table table-bordered">

              <thead>

                <tr>
                  <th>Date</th>
                  <th>Critical</th>
                  <th>High</th>
                  <th>Medium</th>
                  <th>Low</th>
                </tr>

              </thead>

              <tbody>

                {Array.isArray(
                  dashboard.vulnerability_trend
                ) &&
                dashboard.vulnerability_trend.length > 0 ? (
                  dashboard.vulnerability_trend.map(
                    (item, index) => (
                      <tr key={index}>

                        <td>
                          {item.date}
                        </td>

                        <td>
                          {item.critical}
                        </td>

                        <td>
                          {item.high}
                        </td>

                        <td>
                          {item.medium}
                        </td>

                        <td>
                          {item.low}
                        </td>

                      </tr>
                    )
                  )
                ) : (
                  <tr>
                    <td
                      colSpan="5"
                      className="text-center"
                    >
                      No vulnerability trend data available.
                    </td>
                  </tr>
                )}

              </tbody>

            </table>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Dashboard;