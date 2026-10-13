
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import api from "../services/api";
import { getProjects } from "../services/projectService";
import { getScans } from "../services/scanService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function Reports() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
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

            const projectResponse = projectsResult.value;
            const projectData =
                projectResponse?.data ?? projectResponse;

            const projectList = Array.isArray(projectData)
                ? projectData
                : Array.isArray(projectData?.projects)
                    ? projectData.projects
                    : [];

            setProjects(projectList);

            if (scansResult.status === "fulfilled") {
                const scanResponse = scansResult.value;
                const scanData =
                    scanResponse?.data ?? scanResponse;

                const scanList = Array.isArray(scanData)
                    ? scanData
                    : Array.isArray(scanData?.scans)
                        ? scanData.scans
                        : [];

                setScans(scanList);
            } else {
                console.error(
                    "Could not load scans:",
                    scansResult.reason
                );
                setScans([]);
            }
        } catch (err) {
            console.error("Failed to load reports:", err);

            setError(
                err.userMessage ||
                err.response?.data?.detail ||
                "Unable to load report data. Check your backend connection."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadReports();
    }, [loadReports]);

    const getProjectName = (projectId) => {
        const project = projects.find(
            (item) => String(item.id) === String(projectId)
        );

        return (
            project?.project_name ||
            project?.name ||
            `Project ${projectId ?? "Unknown"}`
        );
    };

    const getScanId = (scan) =>
        scan.id ?? scan.scan_id;

    const getScanStatus = (scan) =>
        scan.status ?? scan.scan_status ?? "Unknown";

    const getFindingCount = (scan) => {
        const findings =
            scan.findings ??
            scan.vulnerabilities ??
            scan.results;

        if (Array.isArray(findings)) {
            return findings.length;
        }

        if (Array.isArray(findings?.findings)) {
            return findings.findings.length;
        }

        if (typeof scan.total_findings === "number") {
            return scan.total_findings;
        }

        if (typeof scan.finding_count === "number") {
            return scan.finding_count;
        }

        return "Not provided";
    };

    const downloadReport = async (scan) => {
        const scanId = getScanId(scan);

        if (scanId == null) {
            alert("The scan ID is unavailable.");
            return;
        }

        setExportingScanId(scanId);

        try {
            // Fetch the full details for this scan.
            const response = await api.get(`/scans/${scanId}`);
            const details = response.data ?? response;

            // Support common API response formats.
            let findings =
                details.findings ??
                details.vulnerabilities ??
                details.results ??
                [];

            if (!Array.isArray(findings)) {
                findings = Array.isArray(findings?.findings)
                    ? findings.findings
                    : Array.isArray(findings?.vulnerabilities)
                        ? findings.vulnerabilities
                        : [];
            }

            const projectId =
                scan.project_id ?? details.project_id ?? null;

            const report = {
                report_generated_at: new Date().toISOString(),
                scan_id: scanId,
                project_id: projectId,
                project_name: getProjectName(projectId),
                scan_status:
                    details.status ??
                    details.scan_status ??
                    getScanStatus(scan),
                findings,
                finding_count: findings.length,
                note:
                    findings.length === 0
                        ? "The scan detail endpoint did not return findings in the expected fields. Check its response structure if this scan is expected to contain vulnerabilities."
                        : "Findings retrieved from the scan detail endpoint.",
            };

            const blob = new Blob(
                [JSON.stringify(report, null, 2)],
                { type: "application/json" }
            );

            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");

            link.href = url;
            link.download = `scan-report-${scanId}.json`;

            document.body.appendChild(link);
            link.click();
            link.remove();

            // Release the temporary download URL after the click.
            window.setTimeout(() => {
                URL.revokeObjectURL(url);
            }, 1000);
        } catch (err) {
            console.error("Failed to export scan report:", err);

            alert(
                err.response?.data?.detail ||
                err.userMessage ||
                "Unable to export scan details. Check that the backend is running."
            );
        } finally {
            setExportingScanId(null);
        }
    };

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Reports</h1>
                <LoadingState message="Loading report data..." />
            </div>
        );
    }

    if (error) {
        return (
            <div
                style={{
                    padding: "30px",
                    maxWidth: "1000px",
                    margin: "0 auto",
                }}
            >
                <h1>Reports</h1>
                <ErrorState
                    message={error}
                    onRetry={loadReports}
                />
            </div>
        );
    }

    const completedScans = scans.filter((scan) => {
        const status = String(getScanStatus(scan)).toLowerCase();

        return [
            "completed",
            "complete",
            "success",
            "successful",
        ].includes(status);
    });

    return (
        <main
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            <h1>Reports</h1>

            <p>
                Review your projects and scan activity,
                and export available scan data.
            </p>

            {/* Summary cards */}
            <section
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: "16px",
                    margin: "25px 0",
                }}
            >
                {[
                    {
                        label: "Total Projects",
                        value: projects.length,
                    },
                    {
                        label: "Total Scans",
                        value: scans.length,
                    },
                    {
                        label: "Completed Scans",
                        value: completedScans.length,
                    },
                ].map((item) => (
                    <div
                        key={item.label}
                        style={{
                            border: "1px solid #ddd",
                            borderRadius: "10px",
                            padding: "20px",
                        }}
                    >
                        <h3>{item.label}</h3>

                        <p
                            style={{
                                fontSize: "30px",
                                fontWeight: "bold",
                                margin: "8px 0 0",
                            }}
                        >
                            {item.value}
                        </p>
                    </div>
                ))}
            </section>

            {/* Project summary */}
            <section style={{ marginTop: "30px" }}>
                <h2>Project Summary</h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create a project before generating reports."
                        buttonText="Go to Projects"
                        onButtonClick={() =>
                            navigate("/projects")
                        }
                    />
                ) : (
                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns:
                                "repeat(auto-fit, minmax(240px, 1fr))",
                            gap: "16px",
                            marginTop: "16px",
                        }}
                    >
                        {projects.map((project) => {
                            const projectScans = scans.filter(
                                (scan) =>
                                    String(scan.project_id) ===
                                    String(project.id)
                            );

                            return (
                                <article
                                    key={project.id}
                                    style={{
                                        border: "1px solid #ddd",
                                        borderRadius: "10px",
                                        padding: "18px",
                                        overflowWrap: "anywhere",
                                    }}
                                >
                                    <h3>
                                        {project.project_name ||
                                            project.name ||
                                            `Project ${project.id}`}
                                    </h3>

                                    <p>
                                        <strong>Project ID:</strong>{" "}
                                        {project.id}
                                    </p>

                                    <p>
                                        <strong>Description:</strong>{" "}
                                        {project.description ||
                                            "No description"}
                                    </p>

                                    <p>
                                        <strong>Total scans:</strong>{" "}
                                        {projectScans.length}
                                    </p>

                                    <button
                                        type="button"
                                        onClick={() => {
                                            localStorage.setItem(
                                                "selected_project_id",
                                                String(project.id)
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

            {/* Scan report table */}
            <section style={{ marginTop: "35px" }}>
                <h2>Scan Reports</h2>

                {scans.length === 0 ? (
                    <p>
                        No scans were returned by the backend.
                        Upload a file and start a scan first.
                    </p>
                ) : (
                    <div style={{ overflowX: "auto" }}>
                        <table
                            style={{
                                width: "100%",
                                borderCollapse: "collapse",
                                marginTop: "16px",
                            }}
                        >
                            <thead>
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
                                            style={{
                                                textAlign: "left",
                                                padding: "12px",
                                                borderBottom:
                                                    "2px solid #ddd",
                                            }}
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
                                        <tr
                                            key={scanId ?? index}
                                        >
                                            <td
                                                style={{
                                                    padding: "12px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {scanId ?? "N/A"}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "12px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {getProjectName(
                                                    scan.project_id
                                                )}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "12px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {getScanStatus(scan)}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "12px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {getFindingCount(scan)}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "12px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                    whiteSpace: "nowrap",
                                                }}
                                            >
                                                <button
                                                    type="button"
                                                    disabled={scanId == null}
                                                    onClick={() => {
                                                        if (scanId != null) {
                                                            navigate(
                                                                "/results",
                                                                {
                                                                    state: {
                                                                        scanId,
                                                                        result: scan,
                                                                    },
                                                                }
                                                            );
                                                        }
                                                    }}
                                                >
                                                    View Results
                                                </button>{" "}

                                                <button
                                                    type="button"
                                                    disabled={
                                                        exportingScanId !== null
                                                    }
                                                    onClick={() =>
                                                        downloadReport(scan)
                                                    }
                                                >
                                                    {String(exportingScanId) ===
                                                    String(scanId)
                                                        ? "Exporting..."
                                                        : "Export JSON"}
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>

            {/* Page actions */}
            <div
                style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: "10px",
                    marginTop: "30px",
                }}
            >
                <button
                    type="button"
                    onClick={loadReports}
                >
                    Refresh Reports
                </button>

                <button
                    type="button"
                    onClick={() => navigate("/projects")}
                >
                    Go to Projects
                </button>

                <button
                    type="button"
                    onClick={() => navigate("/dashboard")}
                >
                    Back to Dashboard
                </button>
            </div>
        </main>
    );
}

export default Reports;