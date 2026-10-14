import { useCallback, useEffect, useMemo, useState } from "react";
import { getProjects } from "../services/projectService";
import { getScans } from "../services/scanService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import DashboardCard from "../components/DashboardCard";

function Dashboard() {
    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const fetchDashboardData = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] = await Promise.allSettled([
                getProjects(),
                getScans(),
            ]);

            if (projectsResult.status === "fulfilled") {
                const data = projectsResult.value;

                const projectList = Array.isArray(data)
                    ? data
                    : Array.isArray(data?.projects)
                      ? data.projects
                      : Array.isArray(data?.data)
                        ? data.data
                        : null;

                if (projectList === null) {
                    throw new Error("Unexpected projects API response.");
                }

                setProjects(projectList);
            } else {
                throw projectsResult.reason;
            }

            if (scansResult.status === "fulfilled") {
                const data = scansResult.value;

                const scanList = Array.isArray(data)
                    ? data
                    : Array.isArray(data?.scans)
                      ? data.scans
                      : Array.isArray(data?.data)
                        ? data.data
                        : null;

                if (scanList === null) {
                    throw new Error("Unexpected scans API response.");
                }

                setScans(scanList);
            } else {
                throw scansResult.reason;
            }
        } catch (err) {
            console.error("Dashboard error:", err);

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    err.message ||
                    "Unable to load dashboard data. Check your login and backend."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchDashboardData();
    }, [fetchDashboardData]);

    const totalVulnerabilities = useMemo(() => {
        return scans.reduce((total, scan) => {
            const count = Number(scan.vulnerability_count ?? 0);

            return total + (
                Number.isFinite(count) && count > 0 ? count : 0
            );
        }, 0);
    }, [scans]);

    if (loading) {
        return (
            <main style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <LoadingState message="Loading dashboard..." />
            </main>
        );
    }

    if (error) {
        return (
            <main style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <ErrorState
                    message={error}
                    onRetry={fetchDashboardData}
                />
            </main>
        );
    }

    return (
        <main
            style={{
                padding: "clamp(16px, 3vw, 30px)",
                maxWidth: "1400px",
                margin: "0 auto",
            }}
        >
            <header>
                <h1>Dashboard</h1>
                <p>Overview of your cybersecurity projects and scans.</p>
            </header>

            <section
                className="row g-3"
                aria-label="Dashboard statistics"
                style={{ marginTop: "25px" }}
            >
                <div className="col-12 col-md-6 col-xl-4">
                    <DashboardCard
                        title="Total Projects"
                        value={projects.length}
                        icon="📁"
                    />
                </div>

                <div className="col-12 col-md-6 col-xl-4">
                    <DashboardCard
                        title="Total Scans"
                        value={scans.length}
                        icon="🔍"
                    />
                </div>

                <div className="col-12 col-md-6 col-xl-4">
                    <DashboardCard
                        title="Vulnerabilities"
                        value={totalVulnerabilities}
                        icon="🛡️"
                    />
                </div>
            </section>

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #e5e7eb",
                    borderRadius: "10px",
                    padding: "20px",
                    backgroundColor: "#ffffff",
                }}
            >
                <h2>Your Projects</h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects yet"
                        message="Create a project to get started."
                    />
                ) : (
                    projects.map((project, index) => (
                        <article
                            key={project.id ?? `project-${index}`}
                            style={{
                                borderBottom: "1px solid #e5e7eb",
                                padding: "15px 0",
                                overflowWrap: "anywhere",
                            }}
                        >
                            <h3>
                                {project.name ??
                                    project.project_name ??
                                    `Project ${project.id ?? ""}`}
                            </h3>

                            <p>
                                {project.description ||
                                    "No description provided."}
                            </p>

                            <p>
                                <strong>Project ID:</strong>{" "}
                                {project.id ?? "Not available"}
                            </p>
                        </article>
                    ))
                )}
            </section>

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #e5e7eb",
                    borderRadius: "10px",
                    padding: "20px",
                    backgroundColor: "#ffffff",
                }}
            >
                <h2>Recent Scans</h2>

                {scans.length === 0 ? (
                    <p>No scans were returned by the backend.</p>
                ) : (
                    scans.map((scan, index) => (
                        <article
                            key={scan.id ?? scan.scan_id ?? `scan-${index}`}
                            style={{
                                borderBottom: "1px solid #e5e7eb",
                                padding: "12px 0",
                                overflowWrap: "anywhere",
                            }}
                        >
                            <p>
                                <strong>Scan ID:</strong>{" "}
                                {scan.id ?? scan.scan_id ?? "Not available"}
                            </p>

                            <p>
                                <strong>Status:</strong>{" "}
                                {scan.status ?? scan.state ?? "Unknown"}
                            </p>

                            <p>
                                <strong>Project ID:</strong>{" "}
                                {scan.project_id ?? "Not available"}
                            </p>

                            {scan.created_at && (
                                <p>
                                    <strong>Created:</strong>{" "}
                                    {new Date(
                                        scan.created_at
                                    ).toLocaleString()}
                                </p>
                            )}

                            <p>
                                <strong>Vulnerabilities:</strong>{" "}
                                {Number(scan.vulnerability_count ?? 0)}
                            </p>
                        </article>
                    ))
                )}
            </section>

            <button
                type="button"
                onClick={fetchDashboardData}
                disabled={loading}
                style={{
                    marginTop: "25px",
                    padding: "10px 16px",
                    border: "1px solid #d1d5db",
                    borderRadius: "8px",
                    cursor: loading ? "not-allowed" : "pointer",
                    opacity: loading ? 0.6 : 1,
                }}
            >
                {loading ? "Refreshing..." : "Refresh Dashboard"}
            </button>
        </main>
    );
}

export default Dashboard;