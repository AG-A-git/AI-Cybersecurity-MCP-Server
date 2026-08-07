import React from "react";
import DashboardCard from "../components/DashboardCard";

function Dashboard() {
  return (
    <div className="container-fluid">

      {/* Welcome Section */}
      <div className="mt-4 mb-4">
        <h2>Welcome, Security Analyst 👋</h2>

        <p>
          Monitor your vulnerability scans and security risks.
        </p>
      </div>


      {/* Dashboard Cards */}
      <div className="row">

        {/* Total Projects */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Total Projects"
            value="26"
            icon="📁"
          />
        </div>


        {/* Total Scans */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Total Scans"
            value="120"
            icon="🔍"
          />
        </div>


        {/* Critical Vulnerabilities */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Critical Vulnerabilities"
            value="18"
            icon="🚨"
          />
        </div>


        {/* High Vulnerabilities */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="High Vulnerabilities"
            value="35"
            icon="⚠️"
          />
        </div>

      </div>


      {/* Medium and Low Cards */}
      <div className="row">

        {/* Medium Vulnerabilities */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Medium Vulnerabilities"
            value="45"
            icon="🟠"
          />
        </div>


        {/* Low Vulnerabilities */}
        <div className="col-md-3 mb-3">
          <DashboardCard
            title="Low Vulnerabilities"
            value="22"
            icon="🟢"
          />
        </div>

      </div>


      {/* Recent Scans */}
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

                <tr>
                  <td>E-Commerce App</td>
                  <td>06 Aug 2026</td>
                  <td>12</td>
                  <td>Completed</td>
                </tr>


                <tr>
                  <td>Banking System</td>
                  <td>05 Aug 2026</td>
                  <td>25</td>
                  <td>Completed</td>
                </tr>


                <tr>
                  <td>Student Portal</td>
                  <td>04 Aug 2026</td>
                  <td>8</td>
                  <td>Completed</td>
                </tr>

              </tbody>

            </table>

          </div>

        </div>

      </div>


      {/* Chart Placeholder */}
      <div className="card mt-4 mb-4">

        <div className="card-body text-center">

          <h5>
            Vulnerability Trend Chart
          </h5>


          <div
            style={{
              height: "250px",
              background: "#f5f5f5",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}
          >
            Chart Area
          </div>

        </div>

      </div>

    </div>
  );
}

export default Dashboard;