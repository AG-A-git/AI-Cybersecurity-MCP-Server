
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getProjects } from "../services/projectService";
import { getScans, getScanResults } from "../services/scanService";
import { downloadScanReport } from "../services/reportService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import "../styles/Reports.css";

const getFindings = (data) => {
    if (Array.isArray(data?.vulnerabilities)) return data.vulnerabilities;
    if (Array.isArray(data?.findings)) return data.findings;
    if (Array.isArray(data?.results?.vulnerabilities)) {
        return data.results.vulnerabilities;
    }
    if (Array.isArray(data?.results?.findings)) {
        return data.results.findings;
    }
    if (Array.isArray(data?.results)) return data.results;
    return [];
};

const getFindingKey = (finding) => {
    const normalize = (value) =>
        String(value ?? "")
            .trim()
            .replace(/\\/g, "/")
            .replace(/\s+/g, " ")
            .toLowerCase();

    return JSON.stringify([
        normalize(finding.file_name ?? finding.filename ?? finding.file),
        normalize(finding.line_number ?? finding.line),
        normalize(
            finding.vulnerability_type ??
                finding.vulnerability ??
                finding.type
        ),
        normalize(finding.severity),
        normalize(
            finding.code ??
                finding.vulnerable_code ??
                finding.source_code ??
                finding.snippet
        ),
    ]);
};

const removeDuplicateFindings = (findings) => {
    const seen = new Set();

    return findings.filter((finding) => {
        const key = getFindingKey(finding);

        if (seen.has(key)) return false;

        seen.add(key);
        return true;
    });
};

const getProjectList = (data) => {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.projects)) return data.projects;
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.data)) return data.data;
    return [];
};

const getScanList = (data) => {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.scans)) return data.scans;
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.data)) return data.data;
    return [];
};

const getScanId = (scan) => scan?.id ?? scan?.scan_id;

const getScanStatus = (scan) =>
    scan?.status ?? scan?.scan_status ?? scan?.state ?? "Unknown";

const getScanFindings = (scan) => {
    const findings =
        scan?.findings ?? scan?.vulnerabilities ?? scan?.results;

    if (Array.isArray(findings)) return findings;
    if (Array.isArray(findings?.findings)) return findings.findings;
    if (Array.isArray(findings?.vulnerabilities)) {
        return findings.vulnerabilities;
    }

    return [];
};

const getSummaryFindingCount = (scan) => {
    const count =
        scan?.total_findings ??
        scan?.finding_count ??
        scan?.findings_count ??
        scan?.vulnerability_count ??
        scan?.total_vulnerabilities;

    if (count === null || count === undefined || count === "") {
        return null;
    }

    const parsed = Number(count);

    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

const getErrorMessage = (error, fallback) => {
    if (error?.userMessage) return error.userMessage;

    const detail = error?.response?.data?.detail;

    if (typeof detail === "string" && detail.trim()) {
        return detail;
    }

    if (typeof error?.message === "string" && error.message.trim()) {
        return error.message;
    }

    return fallback;
};

function Reports() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [findingCounts, setFindingCounts] = useState({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [exportError, setExportError] = useState("");
    const [exportingScanId, setExportingScanId] = useState(null);
    const [exportingFormat, setExportingFormat] = useState(null);

    const loadReports = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] =
                await Promise.allSettled([getProjects(), getScans()]);

            if (projectsResult.status === "rejected") {
                throw projectsResult.reason;
            }

            const projectData =
                projectsResult.value?.data ?? projectsResult.value;

            setProjects(getProjectList(projectData));

            if (scansResult.status === "rejected") {
                throw scansResult.reason;
            }

            const scanData = scansResult.value?.data ?? scansResult.value;
            const scanList = getScanList(scanData);

            setScans(scanList);

            const initialCounts = {};

            scanList.forEach((scan) => {
                const id = getScanId(scan);

                if (id == null) return;

                const findings = getScanFindings(scan);
                const summaryCount = getSummaryFindingCount(scan);

                if (findings.length > 0) {
                    initialCounts[id] =
                        removeDuplicateFindings(findings).length;
                } else if (summaryCount !== null) {
                    initialCounts[id] = summaryCount;
                }
            });

            setFindingCounts(initialCounts);

            const detailResults = await Promise.allSettled(
                scanList
                    .filter((scan) => getScanId(scan) != null)
                    .map(async (scan) => ({
                        id: getScanId(scan),
                        details: await getScanResults(getScanId(scan)),
                    }))
            );

            const resolvedCounts = { ...initialCounts };

            detailResults.forEach((result) => {
                if (result.status !== "fulfilled") {
                    console.warn(
                        "Could not retrieve scan finding count:",
                        result.reason
                    );
                    return;
                }

                const { id, details } = result.value;
                const findings = getFindings(details);

                if (findings.length > 0) {
                    resolvedCounts[id] =
                        removeDuplicateFindings(findings).length;
                } else {
                    const summaryCount = getSummaryFindingCount(details);

                    if (summaryCount !== null) {
                        resolvedCounts[id] = summaryCount;
                    } else if (initialCounts[id] === undefined) {
                        delete resolvedCounts[id];
                    }
                }
            });

            setFindingCounts(resolvedCounts);
        } catch (err) {
            console.error("Failed to load reports:", err);

            setError(
                getErrorMessage(
                    err,
                    "Unable to load report data. Check your backend connection."
                )
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadReports();
    }, [loadReports]);

    const getProjectName = (projectId, scan = null) => {
        const project = projects.find(
            (item) =>
                String(item.id ?? item.project_id) === String(projectId)
        );

        return (
            scan?.project_name ??
            scan?.project?.name ??
            project?.project_name ??
            project?.name ??
            project?.title ??
            `Project ${projectId ?? "Unknown"}`
        );
    };

    const getFindingCount = (scan) => {
        const id = getScanId(scan);

        if (id != null && findingCounts[id] !== undefined) {
            return findingCounts[id];
        }

        const findings = getScanFindings(scan);

        if (findings.length > 0) {
            return removeDuplicateFindings(findings).length;
        }

        const summaryCount = getSummaryFindingCount(scan);

        return summaryCount !== null ? summaryCount : "Not available";
    };

    const downloadReport = async (selectedScan, format = "json") => {
        const scanId = getScanId(selectedScan);
        const normalizedFormat = String(format).toLowerCase();

        setExportError("");

        if (
            scanId == null ||
            String(scanId).trim() === "" ||
            !Number.isSafeInteger(Number(scanId)) ||
            Number(scanId) <= 0
        ) {
            setExportError(
                "A valid scan ID is required to export this report."
            );
            return;
        }

        if (!["json", "html", "pdf"].includes(normalizedFormat)) {
            setExportError("Unsupported report format.");
            return;
        }

        // Open the PDF window during the click so popup blockers
        // are less likely to prevent it.
        let printWindow = null;

        if (normalizedFormat === "pdf") {
            printWindow = window.open("", "_blank");

            if (!printWindow) {
                setExportError(
                    "The print window was blocked. Allow pop-ups and try again."
                );
                return;
            }

            printWindow.document.write(
                "<!doctype html><html><head><title>Preparing report</title></head><body>Preparing report...</body></html>"
            );
            printWindow.document.close();
        }

        setExportingScanId(scanId);
        setExportingFormat(normalizedFormat);

        let objectUrl;

        try {
            const response = await downloadScanReport(
                Number(scanId),
                normalizedFormat
            );

            if (normalizedFormat === "pdf") {
                if (
                    response?.method !== "print" ||
                    typeof response.html !== "string" ||
                    !response.html.trim()
                ) {
                    throw new Error(
                        "The report could not be prepared for printing."
                    );
                }

                let hasPrinted = false;

                const printReport = () => {
                    if (hasPrinted || printWindow.closed) return;

                    hasPrinted = true;
                    printWindow.focus();
                    printWindow.print();
                };

                printWindow.document.open();
                printWindow.document.write(response.html);
                printWindow.document.close();

                // Register the load handler and check the document state
                // to cover both early and late load events.
                printWindow.onload = printReport;

                if (printWindow.document.readyState === "complete") {
                    printReport();
                }

                return;
            }

            if (
                !(response?.blob instanceof Blob) ||
                response.blob.size === 0
            ) {
                throw new Error(
                    "The report generator returned an empty file."
                );
            }

            objectUrl = URL.createObjectURL(response.blob);

            const link = document.createElement("a");
            link.href = objectUrl;
            link.download =
                response.filename ??
                `scan-report-${scanId}.${normalizedFormat}`;
            link.style.display = "none";

            document.body.appendChild(link);

            try {
                link.click();
            } finally {
                link.remove();
            }
        } catch (err) {
            if (printWindow && !printWindow.closed) {
                printWindow.close();
            }

            console.error("Failed to download scan report:", err);

            setExportError(
                getErrorMessage(
                    err,
                    `Unable to export the ${normalizedFormat.toUpperCase()} report. Please try again.`
                )
            );
        } finally {
            if (objectUrl) {
                window.setTimeout(
                    () => URL.revokeObjectURL(objectUrl),
                    1000
                );
            }

            setExportingScanId(null);
            setExportingFormat(null);
        }
    };

    if (loading) {
        return (
            <main className="reports-page">
                <h1 className="reports-title">Reports</h1>
                <LoadingState message="Loading report data..." />
            </main>
        );
    }

    if (error) {
        return (
            <main className="reports-page">
                <h1 className="reports-title">Reports</h1>
                <ErrorState message={error} onRetry={loadReports} />
            </main>
        );
    }

    const completedScans = scans.filter((scan) =>
        ["completed", "complete", "success", "successful"].includes(
            String(getScanStatus(scan)).toLowerCase()
        )
    );

    return (
        <main className="reports-page">
            <header>
                <h1 className="reports-title">Reports</h1>
                <p className="reports-subtitle">
                    Review projects, scan activity, and export security findings.
                </p>
            </header>

            {exportError && (
                <div role="alert" className="reports-export-error">
                    <div className="reports-error-content">
                        <p>{exportError}</p>
                        <button
                            type="button"
                            className="reports-button"
                            onClick={() => setExportError("")}
                        >
                            Dismiss
                        </button>
                    </div>
                </div>
            )}

            <section className="reports-stats">
                {[
                    { label: "Total Projects", value: projects.length },
                    { label: "Total Scans", value: scans.length },
                    {
                        label: "Completed Scans",
                        value: completedScans.length,
                    },
                ].map((item) => (
                    <article key={item.label} className="reports-stat-card">
                        <h2 className="reports-stat-label">{item.label}</h2>
                        <p className="reports-stat-value">{item.value}</p>
                    </article>
                ))}
            </section>

            <section className="reports-section">
                <h2 className="reports-section-title">Project Summary</h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create a project before generating reports."
                        buttonText="Go to Projects"
                        onButtonClick={() => navigate("/projects")}
                    />
                ) : (
                    <div className="reports-project-grid">
                        {projects.map((project, index) => {
                            const projectId =
                                project.id ?? project.project_id;

                            const projectScans = scans.filter(
                                (scan) =>
                                    String(
                                        scan.project_id ?? scan.project?.id
                                    ) === String(projectId)
                            );

                            return (
                                <article
                                    key={projectId ?? `project-${index}`}
                                    className="reports-project-card"
                                >
                                    <h3 className="reports-project-name">
                                        {project.project_name ??
                                            project.name ??
                                            project.title ??
                                            `Project ${projectId}`}
                                    </h3>

                                    <p className="reports-muted">
                                        Project ID: {projectId ?? "Not available"}
                                    </p>

                                    <p className="reports-muted">
                                        {project.description ?? "No description"}
                                    </p>

                                    <p className="reports-muted">
                                        Total scans: {projectScans.length}
                                    </p>

                                    <button
                                        type="button"
                                        className="reports-button reports-button-primary"
                                        onClick={() => {
                                            if (projectId == null) {
                                                setExportError(
                                                    "This project does not have a valid ID."
                                                );
                                                return;
                                            }

                                            localStorage.setItem(
                                                "selected_project_id",
                                                String(projectId)
                                            );

                                            navigate("/upload");
                                        }}
                                    >
                                        Open Project
                                    </button>
                                </article>
                            );
                        })}
                    </div>
                )}
            </section>

            <section className="reports-section">
                <h2 className="reports-section-title">Scan Reports</h2>

                {scans.length === 0 ? (
                    <EmptyState
                        title="No scans found"
                        message="Upload a file and start a scan first."
                        buttonText="Go to Projects"
                        onButtonClick={() => navigate("/projects")}
                    />
                ) : (
                    <div className="reports-table-wrap">
                        <table className="reports-table">
                            <thead>
                                <tr>
                                    {[
                                        "Scan ID",
                                        "Project",
                                        "Status",
                                        "Findings",
                                        "Actions",
                                    ].map((heading) => (
                                        <th key={heading}>{heading}</th>
                                    ))}
                                </tr>
                            </thead>

                            <tbody>
                                {scans.map((scan, index) => {
                                    const scanId = getScanId(scan);

                                    return (
                                        <tr key={scanId ?? index}>
                                            <td>{scanId ?? "N/A"}</td>

                                            <td>
                                                {getProjectName(
                                                    scan.project_id ??
                                                        scan.project?.id,
                                                    scan
                                                )}
                                            </td>

                                            <td>{getScanStatus(scan)}</td>
                                            <td>{getFindingCount(scan)}</td>

                                            <td>
                                                <div className="reports-button-row">
                                                    <button
                                                        type="button"
                                                        disabled={scanId == null}
                                                        className="reports-button"
                                                        onClick={() =>
                                                            navigate("/results", {
                                                                state: {
                                                                    scanId,
                                                                    result: scan,
                                                                },
                                                            })
                                                        }
                                                    >
                                                        View Results
                                                    </button>

                                                    {[
                                                        "json",
                                                        "html",
                                                        "pdf",
                                                    ].map((format) => {
                                                        const isExporting =
                                                            String(
                                                                exportingScanId
                                                            ) ===
                                                                String(scanId) &&
                                                            exportingFormat ===
                                                                format;

                                                        return (
                                                            <button
                                                                key={format}
                                                                type="button"
                                                                disabled={
                                                                    exportingScanId !==
                                                                        null ||
                                                                    scanId == null
                                                                }
                                                                className="reports-button reports-button-primary"
                                                                onClick={() =>
                                                                    downloadReport(
                                                                        scan,
                                                                        format
                                                                    )
                                                                }
                                                            >
                                                                {isExporting
                                                                    ? "Exporting..."
                                                                    : `Export ${format.toUpperCase()}`}
                                                            </button>
                                                        );
                                                    })}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>

            <div className="reports-footer-actions">
                <button
                    type="button"
                    className="reports-button"
                    onClick={loadReports}
                >
                    Refresh Reports
                </button>

                <button
                    type="button"
                    className="reports-button"
                    onClick={() => navigate("/projects")}
                >
                    Go to Projects
                </button>

                <button
                    type="button"
                    className="reports-button"
                    onClick={() => navigate("/dashboard")}
                >
                    Back to Dashboard
                </button>
            </div>
        </main>
    );
}

export default Reports;
