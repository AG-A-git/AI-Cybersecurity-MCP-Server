import React from "react";
import Table from "../components/Table";

const mockResults = [
    {
        id: 1,
        severity: "Critical",
        vulnerability: "SQL Injection",
        description: "User input is directly used in a database query.",
        status: "Open",
    },
    {
        id: 2,
        severity: "High",
        vulnerability: "Cross-Site Scripting (XSS)",
        description: "Untrusted input is rendered without proper sanitization.",
        status: "Open",
    },
    {
        id: 3,
        severity: "Medium",
        vulnerability: "Missing Security Headers",
        description: "Recommended HTTP security headers are missing.",
        status: "Open",
    },
    {
        id: 4,
        severity: "Low",
        vulnerability: "Information Disclosure",
        description: "Server information is exposed in HTTP responses.",
        status: "Resolved",
    },
];

function Results() {
    const headers = [
        "Severity",
        "Vulnerability",
        "Description",
        "Status",
    ];

    const rows = mockResults.map((result) => [
        result.severity,
        result.vulnerability,
        result.description,
        result.status,
    ]);

    return (
        <div className="container-fluid mt-4">

            {/* Page Header */}
            <div className="mb-4">
                <h2>Scan Results</h2>

                <p className="text-muted">
                    View vulnerabilities detected during the scan.
                </p>
            </div>

            {/* Results Table */}
            <div className="card">

                <div className="card-header">
                    <h5 className="mb-0">
                        Vulnerabilities Found
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

export default Results;