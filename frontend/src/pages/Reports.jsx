
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getProjects } from "../services/projectService";
import {
    getScans,
    getScanResults,
} from "../services/scanService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import "../styles/Reports.css";

const getFindings = (data) => {
    if (Array.isArray(data?.vulnerabilities)) {
        return data.vulnerabilities;
    }

    if (Array.isArray(data?.findings)) {
        return data.findings;
    }

    if (Array.isArray(data?.results?.vulnerabilities)) {
        return data.results.vulnerabilities;
    }

    if (Array.isArray(data?.results?.findings)) {
        return data.results.findings;
    }

    if (Array.isArray(data?.results)) {
        return data.results;
    }

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
        normalize(
            finding.file_name ??
                finding.filename ??
                finding.file
        ),
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

        if (seen.has(key)) {
            return false;
        }

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

const getScanId = (scan) => scan.id ?? scan.scan_id;

const getScanStatus = (scan) =>
    scan.status ?? scan.scan_status ?? scan.state ?? "Unknown";

const getScanFindings = (scan) => {
    const findings =
        scan.findings ??
        scan.vulnerabilities ??
        scan.results;

    if (Array.isArray(findings)) {
        return findings;
    }

    if (Array.isArray(findings?.findings)) {
        return findings.findings;
    }

    if (Array.isArray(findings?.vulnerabilities)) {
        return findings.vulnerabilities;
    }

    return [];
};

const getSummaryFindingCount = (scan) => {
    const count =
        scan.total_findings ??
        scan.finding_count ??
        scan.findings_count ??
        scan.vulnerability_count ??
        scan.total_vulnerabilities;

    if (count === null || count === undefined || count === "") {
        return null;
    }

    const parsed = Number(count);

    return Number.isFinite(parsed) && parsed >= 0
        ? parsed
        : null;
};

const getErrorMessage = (error, fallback) => {
    if (error?.userMessage) {
        return error.userMessage;
    }

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

    const loadReports = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] =
                await Promise.allSettled([
                    getProjects(),
                    getScans(),
                ]);

            if (projectsResult.status === "rejected") {
                throw projectsResult.reason;
            }

            const projectData =
                projectsResult.value?.data ?? projectsResult.value;

            const projectList = getProjectList(projectData);
            setProjects(projectList);

            if (scansResult.status === "rejected") {
                throw scansResult.reason;
            }

            const scanData =
                scansResult.value?.data ?? scansResult.value;

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
                    .map(async (scan) => {
                        const id = getScanId(scan);
                        const details = await getScanResults(id);

                        return { id, details };
                    })
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
                    const summaryCount =
                        getSummaryFindingCount(details);

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
                String(item.id ?? item.project_id) ===
                String(projectId)
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

        if (
            id != null &&
            findingCounts[id] !== undefined
        ) {
            return findingCounts[id];
        }

        const findings = getScanFindings(scan);

        if (findings.length > 0) {
            return removeDuplicateFindings(findings).length;
        }

        const summaryCount = getSummaryFindingCount(scan);

        return summaryCount !== null
            ? summaryCount
            : "Not available";
    };

    const downloadReport = async (selectedScan) => {
        const scanId = getScanId(selectedScan);

        setExportError("");

        if (
            scanId == null ||
            String(scanId).trim() === "" ||
            !Number.isInteger(Number(scanId)) ||
            Number(scanId) <= 0
        ) {
            setExportError("A valid scan ID is required to export this report.");
            return;
        }

        setExportingScanId(scanId);

        try {
            const details = await getScanResults(scanId);

            // Validate the response before creating a downloadable report.
            if (
                !details ||
                typeof details !== "object" ||
                Array.isArray(details)
            ) {
                throw new Error(
                    "The backend returned an invalid scan response. Please try again."
                );
            }

            const returnedScanId = details.id ?? details.scan_id;

            if (
                returnedScanId == null ||
                String(returnedScanId) !== String(scanId)
            ) {
                throw new Error(
                    "The scan response did not match the requested scan. Export cancelled."
                );
            }

            const uniqueFindings = removeDuplicateFindings(
                getFindings(details)
            );

            const projectId =
                details.project_id ??
                selectedScan.project_id ??
                details.project?.id ??
                selectedScan.project?.id ??
                null;

            let projectName = getProjectName(projectId, {
                ...selectedScan,
                ...details,
            });

            if (
                projectName ===
                    `Project ${projectId ?? "Unknown"}` &&
                projectId != null
            ) {
                try {
                    const projectsResponse = await getProjects();

                    const projectList = getProjectList(
                        projectsResponse?.data ?? projectsResponse
                    );

                    const project = projectList.find(
                        (item) =>
                            String(item.id ?? item.project_id) ===
                            String(projectId)
                    );

                    projectName =
                        project?.project_name ??
                        project?.name ??
                        project?.title ??
                        projectName;
                } catch (projectError) {
                    console.error(
                        "Could not resolve project name:",
                        projectError
                    );
                }
            }

            const report = {
                report_generated_at: new Date().toISOString(),
                scan_id: Number(returnedScanId),
                project_id: projectId,
                project_name: projectName,
                scan_status:
                    details.status ??
                    details.scan_status ??
                    getScanStatus(selectedScan),
                scan_created_at: details.created_at ?? null,
                risk_score: details.risk_score ?? null,
                risk_level: details.risk_level ?? null,
                vulnerability_count:
                    details.vulnerability_count ??
                    uniqueFindings.length,
                severity_summary: {
                    critical_count: details.critical_count ?? null,
                    high_count: details.high_count ?? null,
                    medium_count: details.medium_count ?? null,
                    low_count: details.low_count ?? null,
                },
                findings: uniqueFindings.map((finding) => ({
                    id: finding.id ?? null,
                    file_name:
                        finding.file_name ??
                        finding.filename ??
                        finding.file ??
                        "Unknown",
                    line_number:
                        finding.line_number ??
                        finding.line ??
                        null,
                    vulnerability_type:
                        finding.vulnerability_type ??
                        finding.vulnerability ??
                        finding.type ??
                        "Unknown",
                    severity: finding.severity ?? "Unknown",
                    confidence: finding.confidence ?? null,
                    code:
                        finding.code ??
                        finding.vulnerable_code ??
                        finding.source_code ??
                        finding.snippet ??
                        "",
                    explanation:
                        finding.explanation ??
                        finding.description ??
                        finding.message ??
                        null,
                    ai_analysis:
                        typeof finding.ai_analysis === "string"
                            ? finding.ai_analysis
                            : null,
                    recommendation:
                        finding.recommendation ??
                        finding.remediation ??
                        finding.fix ??
                        null,
                })),
                finding_count: uniqueFindings.length,
                note: "Findings retrieved from the scan detail endpoint. This JSON file is generated by the frontend.",
            };

            const blob = new Blob(
                [JSON.stringify(report, null, 2)],
                { type: "application/json;charset=utf-8" }
            );

            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");

            try {
                link.href = url;
                link.download = `scan-report-${scanId}.json`;
                link.style.display = "none";

                document.body.appendChild(link);
                link.click();
            } finally {
                link.remove();
                window.setTimeout(() => URL.revokeObjectURL(url), 1000);
            }
        } catch (err) {
            console.error("Failed to export scan report:", err);

            setExportError(
                getErrorMessage(
                    err,
                    "Unable to export scan details. Please try again."
                )
            );
        } finally {
            setExportingScanId(null);
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
                <ErrorState
                    message={error}
                    onRetry={loadReports}
                />
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
                <div
                    role="alert"
                    className="reports-export-error"
                >
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
                    <article
                        key={item.label}
                        className="reports-stat-card"
                    >
                        <h2 className="reports-stat-label">
                            {item.label}
                        </h2>
                        <p className="reports-stat-value">
                            {item.value}
                        </p>
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
                                        scan.project_id ??
                                        scan.project?.id
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
                            <thead >
                                <tr>
                                    {[
                                        "Scan ID",
                                        "Project",
                                        "Status",
                                        "Findings",
                                        "Actions",
                                    ].map((heading) => (
                                        <th
                                            key={heading}

                                        >
                                            {heading}
                                        </th>
                                    ))}
                                </tr>
                            </thead>

                            <tbody>
                                {scans.map((scan, index) => {
                                    const scanId = getScanId(scan);

                                    return (
                                        <tr key={scanId ?? index}>
                                            <td >
                                                {scanId ?? "N/A"}
                                            </td>

                                            <td >
                                                {getProjectName(
                                                    scan.project_id ??
                                                        scan.project?.id,
                                                    scan
                                                )}
                                            </td>

                                            <td >
                                                {getScanStatus(scan)}
                                            </td>

                                            <td >
                                                {getFindingCount(scan)}
                                            </td>

                                            <td >
                                                <div className="reports-button-row">
                                                    <button
                                                        type="button"
                                                        disabled={scanId == null}
                                                        className="reports-button"
                                                        onClick={() => {
                                                            navigate("/results", {
                                                                state: {
                                                                    scanId,
                                                                    result: scan,
                                                                },
                                                            });
                                                        }}
                                                    >
                                                        View Results
                                                    </button>

                                                    <button
                                                        type="button"
                                                        disabled={
                                                            exportingScanId !== null ||
                                                            scanId == null
                                                        }
                                                        className="reports-button reports-button-primary"
                                                        onClick={() =>
                                                            downloadReport(scan)
                                                        }
                                                    >
                                                        {String(exportingScanId) ===
                                                        String(scanId)
                                                            ? "Exporting..."
                                                            : "Export JSON"}
                                                    </button>
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
