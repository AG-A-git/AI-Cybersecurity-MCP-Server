
import { useCallback, useEffect, useState } from "react";
import { getProjects } from "../services/projectService";
import { getScans } from "../services/scanService";
import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function getList(response, keys = []) {
    if (Array.isArray(response)) return response;

    for (const key of keys) {
        if (Array.isArray(response?.[key])) {
            return response[key];
        }
    }

    if (Array.isArray(response?.data)) {
        return response.data;
    }

    return [];
}

function History() {
    const [scans, setScans] = useState([]);
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const loadHistory = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] =
                await Promise.allSettled([
                    getProjects(),
                    getScans(),
                ]);

            if (projectsResult.status === "fulfilled") {
                setProjects(
                    getList(projectsResult.value, ["projects"])
                );
            } else {
                console.error(
                    "Failed to load projects:",
                    projectsResult.reason
                );
                setProjects([]);
            }

            if (scansResult.status === "fulfilled") {
                setScans(
                    getList(scansResult.value, ["scans"])
                );
            } else {
                console.error(
                    "Failed to load scans:",
                    scansResult.reason
                );

                throw scansResult.reason;
            }
        } catch (err) {
            console.error("History loading error:", err);
            setError(
                err.userMessage ||
                err.response?.data?.detail ||
                "Unable to load scan history. Please try again."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadHistory();
    }, [loadHistory]);

    const getProjectName = (scan) => {
        const projectId = scan.project_id ?? scan.projectId;

        const project = projects.find(
            (item) => String(item.id) === String(projectId)
        );

        return (
            scan.project_name ||
            project?.project_name ||
            project?.name ||
            (projectId != null ? `Project ${projectId}` : "Unknown project")
        );
    };

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Upload History</h1>
                <LoadingState message="Loading history..." />
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Upload History</h1>
                <ErrorState message={error} onRetry={loadHistory} />
            </div>
        );
    }

    return (
        <div style={{ padding: "30px" }}>
            <h1>Upload History</h1>

            <p>
                Review previous scans for your cybersecurity projects.
            </p>

            {scans.length === 0 ? (
                <EmptyState
                    title="No scan history yet"
                    message="Upload a source file and start a scan to see scan records here."
                />
            ) : (
                <div
                    style={{
                        marginTop: "25px",
                        display: "grid",
                        gap: "15px",
                    }}
                >
                    {scans.map((scan, index) => {
                        const scanId = scan.scan_id ?? scan.id;
                        const findings =
                            scan.results ??
                            scan.findings ??
                            scan.vulnerabilities ??
                            [];

                        return (
                            <article
                                key={scanId ?? index}
                                style={{
                                    border: "1px solid #ddd",
                                    borderRadius: "8px",
                                    padding: "20px",
                                    background: "#fff",
                                }}
                            >
                                <h2>
                                    {getProjectName(scan)}
                                </h2>

                                <p>
                                    <strong>Scan ID:</strong>{" "}
                                    {scanId ?? "N/A"}
                                </p>

                                <p>
                                    <strong>Project ID:</strong>{" "}
                                    {scan.project_id ?? "N/A"}
                                </p>

                                <p>
                                    <strong>Status:</strong>{" "}
                                    {scan.status ?? "Completed"}
                                </p>

                                <p>
                                    <strong>Findings:</strong>{" "}
                                    {Array.isArray(findings)
                                        ? findings.length
                                        : scan.vulnerability_count ??
                                          scan.total_vulnerabilities ??
                                          "N/A"}
                                </p>

                                <p>
                                    <strong>Scan date:</strong>{" "}
                                    {scan.created_at || scan.started_at
                                        ? new Date(
                                              scan.created_at ??
                                              scan.started_at
                                          ).toLocaleString()
                                        : "N/A"}
                                </p>
                            </article>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

export default History;
