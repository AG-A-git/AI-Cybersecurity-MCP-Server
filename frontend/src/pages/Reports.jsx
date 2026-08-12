import React from "react";
import Table from "../components/Table";

const mockReports = [
  {
    id: 1,
    reportName: "E-Commerce API Security Report",
    scanDate: "2026-08-08",
  },
  {
    id: 2,
    reportName: "Banking Application Security Report",
    scanDate: "2026-08-07",
  },
  {
    id: 3,
    reportName: "Student Portal Security Report",
    scanDate: "2026-08-06",
  },
  {
    id: 4,
    reportName: "Healthcare API Security Report",
    scanDate: "2026-08-05",
  },
  {
    id: 5,
    reportName: "Payment Service Security Report",
    scanDate: "2026-08-04",
  },
];

function Reports() {
  const headers = [
    "Report Name",
    "Scan Date",
  ];

  // Convert reports into objects matching Table headers
  const rows = mockReports.map((report) => ({
    "Report Name": report.reportName,
    "Scan Date": report.scanDate,
  }));

  const actions = (row) => {
    return (
      <div className="d-flex gap-2">

        {/* PDF */}
        <button
          type="button"
          className="btn btn-sm btn-danger"
          onClick={() =>
            alert(
              `PDF download for "${row["Report Name"]}" will be connected later.`
            )
          }
        >
          PDF
        </button>

        {/* HTML */}
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() =>
            alert(
              `HTML download for "${row["Report Name"]}" will be connected later.`
            )
          }
        >
          HTML
        </button>

        {/* JSON */}
        <button
          type="button"
          className="btn btn-sm btn-success"
          onClick={() =>
            alert(
              `JSON download for "${row["Report Name"]}" will be connected later.`
            )
          }
        >
          JSON
        </button>

      </div>
    );
  };

  return (
    <div className="container-fluid mt-4">

      {/* Page Header */}
      <div className="mb-4">
        <h2>Reports</h2>

        <p className="text-muted">
          Download security scan reports in different formats.
        </p>
      </div>

      {/* Reports Card */}
      <div className="card">

        <div className="card-header">
          <h5 className="mb-0">
            Available Reports
          </h5>
        </div>

        <div className="card-body">

          <Table
            headers={headers}
            rows={rows}
            actions={actions}
          />

        </div>

      </div>

    </div>
  );
}

export default Reports;