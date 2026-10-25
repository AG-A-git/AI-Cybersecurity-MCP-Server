
import { getScanResults } from "./scanService";
import { deduplicateFindings } from "../utils/duplicateFindings";

const VALID_FORMATS = new Set(["json", "html", "pdf"]);

const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const getFindings = (data) => {
  let findings = [];

  if (Array.isArray(data?.vulnerabilities)) {
    findings = data.vulnerabilities;
  } else if (Array.isArray(data?.findings)) {
    findings = data.findings;
  } else if (Array.isArray(data?.results?.vulnerabilities)) {
    findings = data.results.vulnerabilities;
  } else if (Array.isArray(data?.results?.findings)) {
    findings = data.results.findings;
  } else if (Array.isArray(data?.results)) {
    findings = data.results;
  }

  return deduplicateFindings(findings);
};

const getField = (finding, ...keys) => {
  for (const key of keys) {
    const value = finding?.[key];

    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }

  return "Not available";
};

const buildHtmlReport = (scan) => {
  const findings = getFindings(scan);
  const scanId = scan.id ?? scan.scan_id ?? "Unknown";
  const projectId = scan.project_id ?? "Unknown";
  const status = scan.status ?? "Unknown";
  const riskScore = scan.risk_score ?? "Not available";
  const riskLevel = scan.risk_level ?? "Not available";
  const createdAt = scan.created_at ?? "Not available";

  const rows = findings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(
            getField(finding, "file_name", "file", "filename")
          )}</td>
          <td>${escapeHtml(
            getField(finding, "line_number", "line")
          )}</td>
          <td>${escapeHtml(
            getField(
              finding,
              "vulnerability_type",
              "vulnerability",
              "type"
            )
          )}</td>
          <td>${escapeHtml(finding.severity ?? "Unknown")}</td>
          <td>${escapeHtml(finding.confidence ?? "N/A")}</td>
          <td>${escapeHtml(
            getField(finding, "cwe", "cwe_id")
          )}</td>
          <td>${escapeHtml(
            getField(finding, "owasp", "owasp_category")
          )}</td>
          <td>
            <pre>${escapeHtml(
              getField(finding, "code", "vulnerable_code")
            )}</pre>
          </td>
          <td>${escapeHtml(
            getField(finding, "explanation", "ai_analysis")
          )}</td>
          <td>${escapeHtml(
            getField(
              finding,
              "recommendation",
              "remediation",
              "fix"
            )
          )}</td>
        </tr>
      `
    )
    .join("");

  const emptyRow = `
    <tr>
      <td colspan="10" class="empty">
        No vulnerabilities were reported for this scan.
      </td>
    </tr>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Scan Report - Scan ${escapeHtml(scanId)}</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 24px;
      color: #1f2937;
      background: #ffffff;
      font-family: Arial, Helvetica, sans-serif;
      font-size: 12px;
      line-height: 1.5;
    }

    h1 {
      margin-bottom: 6px;
      color: #111827;
      font-size: 24px;
    }

    h2 {
      margin-top: 26px;
      color: #111827;
      font-size: 17px;
    }

    .subtitle {
      margin-bottom: 20px;
      color: #6b7280;
    }

    .summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }

    .summary-item {
      padding: 12px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      overflow-wrap: anywhere;
    }

    .summary-label {
      display: block;
      margin-bottom: 4px;
      color: #6b7280;
      font-size: 11px;
    }

    .summary-value {
      color: #111827;
      font-size: 14px;
      font-weight: bold;
    }

    .table-wrapper {
      width: 100%;
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th,
    td {
      padding: 8px;
      border: 1px solid #d1d5db;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }

    th {
      color: #111827;
      background: #f3f4f6;
      font-weight: bold;
    }

    td pre {
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      font-family: Consolas, "Courier New", monospace;
      font-size: 10px;
    }

    .empty {
      padding: 20px;
      text-align: center;
      color: #6b7280;
    }

    .footer {
      margin-top: 24px;
      color: #6b7280;
      font-size: 10px;
    }

    @media screen {
      body {
        max-width: 1800px;
        margin: 24px auto;
        padding: 0 20px;
      }
    }

    @media print {
      @page {
        size: landscape;
        margin: 10mm;
      }

      body {
        margin: 0;
        font-size: 9px;
      }

      h1 {
        font-size: 19px;
      }

      h2 {
        font-size: 13px;
      }

      .summary {
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 6px;
      }

      .summary-item {
        padding: 6px;
        break-inside: avoid;
      }

      .table-wrapper {
        overflow: visible;
      }

      table {
        font-size: 8px;
      }

      th,
      td {
        padding: 4px;
      }

      td pre {
        font-size: 7px;
      }

      thead {
        display: table-header-group;
      }

      tr {
        break-inside: avoid;
        page-break-inside: avoid;
      }

      .footer {
        margin-top: 12px;
      }
    }
  </style>
</head>

<body>
  <h1>Security Scan Report</h1>
  <p class="subtitle">
    Vulnerability assessment and remediation details
  </p>

  <section class="summary">
    <div class="summary-item">
      <span class="summary-label">Scan ID</span>
      <span class="summary-value">${escapeHtml(scanId)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Project ID</span>
      <span class="summary-value">${escapeHtml(projectId)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Status</span>
      <span class="summary-value">${escapeHtml(status)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Risk Score</span>
      <span class="summary-value">${escapeHtml(riskScore)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Risk Level</span>
      <span class="summary-value">${escapeHtml(riskLevel)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Total Findings</span>
      <span class="summary-value">${escapeHtml(findings.length)}</span>
    </div>

    <div class="summary-item">
      <span class="summary-label">Created At</span>
      <span class="summary-value">${escapeHtml(createdAt)}</span>
    </div>
  </section>

  <h2>Findings (${escapeHtml(findings.length)})</h2>

  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>File</th>
          <th>Line</th>
          <th>Vulnerability</th>
          <th>Severity</th>
          <th>Confidence</th>
          <th>CWE</th>
          <th>OWASP</th>
          <th>Code</th>
          <th>Analysis</th>
          <th>Recommendation</th>
        </tr>
      </thead>

      <tbody>
        ${rows || emptyRow}
      </tbody>
    </table>
  </div>

  <p class="footer">
    Generated by AI Cybersecurity MCP. Findings are based on the
    scan results available at report generation time. Review findings
    and validate remediation before deployment.
  </p>
</body>
</html>`;
};

export const downloadScanReport = async (scanId, format = "json") => {
  const numericScanId = Number(scanId);

  if (
    !Number.isSafeInteger(numericScanId) ||
    numericScanId <= 0
  ) {
    throw new Error("A valid scan ID is required to export a report.");
  }

  const normalizedFormat = String(format).toLowerCase();

  if (!VALID_FORMATS.has(normalizedFormat)) {
    throw new Error(
      "Unsupported report format. Choose JSON, HTML, or PDF."
    );
  }

  const scan = await getScanResults(numericScanId);

  if (!scan || typeof scan !== "object" || Array.isArray(scan)) {
    throw new Error("The scan report could not be loaded.");
  }

  const findings = getFindings(scan);

  if (normalizedFormat === "pdf") {
    return {
      method: "print",
      scanId: numericScanId,
      html: buildHtmlReport(scan),
    };
  }

  const filename = `scan-report-${numericScanId}.${normalizedFormat}`;

  if (normalizedFormat === "json") {
    const report = {
      scan_id: scan.id ?? scan.scan_id ?? numericScanId,
      project_id: scan.project_id ?? null,
      status: scan.status ?? "Unknown",
      risk_score: scan.risk_score ?? null,
      risk_level: scan.risk_level ?? null,
      created_at: scan.created_at ?? null,
      vulnerability_count: findings.length,
      findings,
    };

    return {
      blob: new Blob(
        [JSON.stringify(report, null, 2)],
        { type: "application/json;charset=utf-8" }
      ),
      filename,
    };
  }

  return {
    blob: new Blob(
      [buildHtmlReport(scan)],
      { type: "text/html;charset=utf-8" }
    ),
    filename,
  };
};
