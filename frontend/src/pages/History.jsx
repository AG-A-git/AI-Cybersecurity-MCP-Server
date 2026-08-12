import React, { useState } from "react";
import Table from "../components/Table";

const mockHistory = [
  {
    id: 1,
    date: "2026-08-08",
    projectName: "E-Commerce API",
    vulnerabilities: 8,
    status: "Completed",
  },
  {
    id: 2,
    date: "2026-08-07",
    projectName: "Banking Application",
    vulnerabilities: 3,
    status: "Completed",
  },
  {
    id: 3,
    date: "2026-08-06",
    projectName: "Student Portal",
    vulnerabilities: 12,
    status: "Completed",
  },
  {
    id: 4,
    date: "2026-08-05",
    projectName: "Healthcare API",
    vulnerabilities: 0,
    status: "Completed",
  },
  {
    id: 5,
    date: "2026-08-04",
    projectName: "Payment Service",
    vulnerabilities: 6,
    status: "Failed",
  },
];

function History() {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");

  // Search + status filter
  const filteredHistory = mockHistory.filter((scan) => {
    const matchesSearch = scan.projectName
      .toLowerCase()
      .includes(search.toLowerCase());

    const matchesStatus =
      statusFilter === "All" ||
      scan.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  // Table headers
  const headers = [
    "Date",
    "Project Name",
    "Vulnerabilities",
    "Status",
  ];

  // Convert data into objects matching headers
  const rows = filteredHistory.map((scan) => ({
    Date: scan.date,
    "Project Name": scan.projectName,
    Vulnerabilities: scan.vulnerabilities,
    Status: scan.status,
  }));

  return (
    <div className="container-fluid mt-4">

      {/* Page Title */}
      <div className="mb-4">
        <h2>Scan History</h2>

        <p className="text-muted">
          View your previous vulnerability scans.
        </p>
      </div>

      {/* Search and Filter */}
      <div className="row mb-4">

        {/* Search */}
        <div className="col-md-6 mb-2">
          <input
            type="text"
            className="form-control"
            placeholder="Search projects..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Status Filter */}
        <div className="col-md-3 mb-2">
          <select
            className="form-select"
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value)
            }
          >
            <option value="All">All</option>

            <option value="Completed">
              Completed
            </option>

            <option value="Failed">
              Failed
            </option>

            <option value="Running">
              Running
            </option>
          </select>
        </div>

      </div>

      {/* History Table */}
      <div className="card">

        <div className="card-header">
          <h5 className="mb-0">
            Previous Scans
          </h5>
        </div>

        <div className="card-body">

          <Table
            headers={headers}
            rows={rows}
          />

        </div>

      </div>

    </div>
  );
}

export default History;