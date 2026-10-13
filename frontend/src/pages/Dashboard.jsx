import { useCallback, useEffect, useState } from "react";
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
                            : [];

                setProjects(projectList);
            } else {
                console.error("Projects request failed:", projectsResult.reason);
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
                            : [];

                setScans(scanList);
            } else {
                console.error("Scans request failed:", scansResult.reason);
                setScans([]);
            }
        } catch (err) {
            console.error("Dashboard error:", err);
            setError(
                err.userMessage ||
                err.response?.data?.detail ||
                "Unable to load projects. Check that you are logged in and the backend is running."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchDashboardData();
    }, [fetchDashboardData]);

    const totalVulnerabilities = scans.reduce((total, scan) => {
        const results = scan.results ?? scan.findings ?? scan.vulnerabilities;

        if (Array.isArray(results)) {
            return total + results.length;
        }

        const count = Number(
            scan.vulnerability_count ?? scan.total_vulnerabilities ?? 0
        );

        return total + (Number.isFinite(count) ? count : 0);
    }, 0);

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <LoadingState message="Loading dashboard..." />
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <ErrorState message={error} onRetry={fetchDashboardData} />
            </div>
        );
    }

    return (
        <div style={{ padding: "30px" }}>
            <h1>Dashboard</h1>
            <p>Overview of your cybersecurity projects and scans.</p>

            <section
                className="row g-3"
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
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Your Projects</h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects yet"
                        message="No projects were returned by the backend. Check GET /projects/ in Swagger."
                    />
                ) : (
                    projects.map((project) => (
                        <div
                            key={project.id}
                            style={{
                                borderBottom: "1px solid #ddd",
                                padding: "15px 0",
                            }}
                        >
                            <h3>
                                {project.project_name ??
                                    project.name ??
                                    `Project ${project.id}`}
                            </h3>

                            <p>
                                {project.description ||
                                    "No description provided."}
                            </p>

                            <p>
                                <strong>Project ID:</strong> {project.id}
                            </p>
                        </div>
                    ))
                )}
            </section>

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Recent Scans</h2>

                {scans.length === 0 ? (
                    <p>No scans were returned by the backend.</p>
                ) : (
                    scans.map((scan, index) => (
                        <div
                            key={scan.id ?? scan.scan_id ?? index}
                            style={{
                                borderBottom: "1px solid #ddd",
                                padding: "12px 0",
                            }}
                        >
                            <p>
                                <strong>
                                    Scan ID:
                                </strong>{" "}
                                {scan.scan_id ?? scan.id ?? "Not available"}
                            </p>

                            <p>
                                <strong>Status:</strong>{" "}
                                {scan.status ?? scan.state ?? "Completed"}
                            </p>

                            <p>
                                <strong>Project ID:</strong>{" "}
                                {scan.project_id ?? "Not available"}
                            </p>
                        </div>
                    ))
                )}
            </section>

            <button
                type="button"
                onClick={fetchDashboardData}
                style={{
                    marginTop: "25px",
                    padding: "10px 16px",
                    cursor: "pointer",
                }}
            >
                Refresh Dashboard
            </button>
        </div>
    );
}

export default Dashboard;