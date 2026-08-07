import React from "react";
import "./../styles/Results.css";

function Results() {
  const vulnerabilities = [
    {
      file: "login.py",
      line: 42,
      vulnerability: "SQL Injection",
      severity: "Critical",
      risk: 9.8,
      explanation:
        "User input is directly included in a database query without proper validation.",
      recommendation:
        "Use parameterized queries or prepared statements.",
    },
    {
      file: "auth.js",
      line: 18,
      vulnerability: "Hardcoded Password",
      severity: "High",
      risk: 8.2,
      explanation:
        "A sensitive password is stored directly inside the source code.",
      recommendation:
        "Move secrets to environment variables or a secure secret manager.",
    },
    {
      file: "upload.py",
      line: 67,
      vulnerability: "Unvalidated File Upload",
      severity: "High",
      risk: 7.8,
      explanation:
        "Uploaded files are accepted without sufficient type or content validation.",
      recommendation:
        "Validate file type, size, and content before processing uploads.",
    },
    {
      file: "dashboard.jsx",
      line: 31,
      vulnerability: "Cross-Site Scripting",
      severity: "Medium",
      risk: 5.6,
      explanation:
        "Untrusted data may be rendered without appropriate sanitization.",
      recommendation:
        "Sanitize user-controlled data before rendering it.",
    },
    {
      file: "config.py",
      line: 12,
      vulnerability: "Information Disclosure",
      severity: "Low",
      risk: 3.2,
      explanation:
        "Sensitive application information may be exposed through configuration output.",
      recommendation:
        "Remove sensitive information from logs and restrict configuration access.",
    },
  ];

  const critical = vulnerabilities.filter(
    (item) => item.severity === "Critical"
  ).length;

  const high = vulnerabilities.filter(
    (item) => item.severity === "High"
  ).length;

  const medium = vulnerabilities.filter(
    (item) => item.severity === "Medium"
  ).length;

  const low = vulnerabilities.filter(
    (item) => item.severity === "Low"
  ).length;

  const getSeverityClass = (severity) => {
    switch (severity) {
      case "Critical":
        return "severity critical";
      case "High":
        return "severity high";
      case "Medium":
        return "severity medium";
      case "Low":
        return "severity low";
      default:
        return "severity";
    }
  };

  return (
    <div className="results-page">
      <h1>Scan Results</h1>

      <p className="subtitle">
        Vulnerabilities detected during the security scan.
      </p>

      <div className="summary-container">
        <div className="summary-card">
          <h3>Total Issues</h3>
          <p>{vulnerabilities.length}</p>
        </div>

        <div className="summary-card">
          <h3>Critical</h3>
          <p>{critical}</p>
        </div>

        <div className="summary-card">
          <h3>High</h3>
          <p>{high}</p>
        </div>

        <div className="summary-card">
          <h3>Medium</h3>
          <p>{medium}</p>
        </div>

        <div className="summary-card">
          <h3>Low</h3>
          <p>{low}</p>
        </div>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Line Number</th>
              <th>Vulnerability</th>
              <th>Severity</th>
              <th>Risk Score</th>
              <th>AI Explanation</th>
              <th>Recommendation</th>
            </tr>
          </thead>

          <tbody>
            {vulnerabilities.map((item, index) => (
              <tr key={index}>
                <td>{item.file}</td>

                <td>{item.line}</td>

                <td className="vulnerability-name">
                  {item.vulnerability}
                </td>

                <td>
                  <span className={getSeverityClass(item.severity)}>
                    {item.severity}
                  </span>
                </td>

                <td className="risk-score">{item.risk}</td>

                <td>{item.explanation}</td>

                <td>{item.recommendation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Results;