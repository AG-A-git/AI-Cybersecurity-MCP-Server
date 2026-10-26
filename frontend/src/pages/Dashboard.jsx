import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getProjects } from "../services/projectService";
import { getScans, getScanResults } from "../services/scanService";
import { normalizeVulnerability } from "../utils/vulnerabilityUtils";
import { deduplicateFindings } from "../utils/duplicateFindings";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import DashboardCard from "../components/DashboardCard";

import "../styles/Dashboard.css";

const EMPTY_SEVERITY_COUNTS = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
};

function getListResponse(data, property) {
    if (Array.isArray(data)) {
        return data;
    }

    if (Array.isArray(data?.[property])) {
        return data[property];
    }

    if (Array.isArray(data?.data)) {
        return data.data;
    }

    return null;
}

function getFindingsFromResponse(data) {
    if (Array.isArray(data?.vulnerabilities)) {
        return data.vulnerabilities;
    }

    if (Array.isArray(data?.results)) {
        return data.results;
    }

    if (Array.isArray(data?.data?.vulnerabilities)) {
        return data.data.vulnerabilities;
    }

    if (Array.isArray(data?.data?.results)) {
        return data.data.results;
    }

    return null;
}

function Dashboard() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [totalFindings, setTotalFindings] = useState(null);
    const [severityCounts, setSeverityCounts] = useState(null);

    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [analyticsError, setAnalyticsError] = useState("");

    const fetchDashboardData = useCallback(async () => {
        setLoading(true);
        setError("");
        setAnalyticsError("");
        setTotalFindings(null);
        setSeverityCounts(null);

        try {
            const [projectsResult, scansResult] = await Promise.allSettled([
                getProjects(),
                getScans(),
            ]);

            if (projectsResult.status === "rejected") {
                throw projectsResult.reason;
            }

            if (scansResult.status === "rejected") {
                throw scansResult.reason;
            }

            const projectList = getListResponse(
                projectsResult.value,
                "projects"
            );

            const scanList = getListResponse(
                scansResult.value,
                "scans"
            );

            if (projectList === null) {
                throw new Error("Unexpected projects API response.");
            }

            if (scanList === null) {
                throw new Error("Unexpected scans API response.");
            }

            setProjects(projectList);
            setScans(scanList);

            // No scans means the actual finding count is zero.
            if (scanList.length === 0) {
                setTotalFindings(0);
                setSeverityCounts({ ...EMPTY_SEVERITY_COUNTS });
                return;
            }

            // Fetch the actual findings for each scan.
            const scanResults = await Promise.allSettled(
                scanList.map((scan) => {
                    const scanId = scan.id ?? scan.scan_id;

                    if (
                        scanId === null ||
                        scanId === undefined ||
                        String(scanId).trim() === ""
                    ) {
                        throw new Error("A scan is missing its ID.");
                    }

                    return getScanResults(scanId);
                })
            );

            const failedRequests = scanResults.filter(
                (result) => result.status === "rejected"
            );

            // Do not report partial analytics as complete totals.
            if (failedRequests.length > 0) {
                console.error(
                    "Some scan details could not be loaded:",
                    failedRequests.map((result) => result.reason)
                );

                setAnalyticsError(
                    `Could not load findings for ${failedRequests.length} of ${scanList.length} scans. Refresh to try again.`
                );

                return;
            }

            const counts = { ...EMPTY_SEVERITY_COUNTS };
            let findingCount = 0;

            for (const scanResult of scanResults) {
                const detail = scanResult.value;
                const rawFindings = getFindingsFromResponse(detail);

                if (rawFindings === null) {
                    throw new Error(
                        "A scan returned an unexpected findings response."
                    );
                }

                // Use the same normalization and deduplication rules
                // as the Scan Results page.
                const normalizedFindings = rawFindings.map((finding) =>
                    normalizeVulnerability(finding, detail)
                );

                const uniqueFindings = deduplicateFindings(
                    normalizedFindings
                );

                findingCount += uniqueFindings.length;

                for (const finding of uniqueFindings) {
                    const severity = String(
                        finding.severity ?? ""
                    ).trim().toLowerCase();

                    if (
                        Object.prototype.hasOwnProperty.call(
                            counts,
                            severity
                        )
                    ) {
                        counts[severity] += 1;
                    }
                }
            }

            setTotalFindings(findingCount);
            setSeverityCounts(counts);
        } catch (err) {
            console.error("Dashboard error:", err);

            setError(
                err?.userMessage ||
                    err?.response?.data?.detail ||
                    err?.message ||
                    "Unable to load dashboard data. Check your login and backend."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchDashboardData();
    }, [fetchDashboardData]);

    const totalScans = scans.length;

    const totalSeverityFindings = useMemo(() => {
        if (severityCounts === null) {
            return null;
        }

        return Object.values(severityCounts).reduce(
            (total, count) => total + count,
            0
        );
    }, [severityCounts]);

    if (loading) {
        return (
            <div className="dashboard">
                <header className="dashboard__header">
                    <div>
                        <h1 className="dashboard__title">
                            Security Dashboard
                        </h1>
                        <p className="dashboard__subtitle">
                            Overview of your cybersecurity projects and scans.
                        </p>
                    </div>
                </header>

                <LoadingState message="Loading dashboard and scan analytics..." />
            </div>
        );
    }

    if (error) {
        return (
            <div className="dashboard">
                <header className="dashboard__header">
                    <div>
                        <h1 className="dashboard__title">
                            Security Dashboard
                        </h1>
                        <p className="dashboard__subtitle">
                            Overview of your cybersecurity projects and scans.
                        </p>
                    </div>
                </header>

                <ErrorState
                    message={error}
                    onRetry={fetchDashboardData}
                />
            </div>
        );
    }

    return (
        <div className="dashboard">
            <header className="dashboard__header">
                <div>
                    <h1 className="dashboard__title">
                        Security Dashboard
                    </h1>
                    <p className="dashboard__subtitle">
                        Monitor your projects, scans, and detected vulnerabilities.
                    </p>
                </div>

                <button
                    type="button"
                    className="dashboard__button"
                    onClick={fetchDashboardData}
                    disabled={loading}
                >
                    Refresh dashboard
                </button>
            </header>

            <section
                className="dashboard__stats"
                aria-label="Dashboard statistics"
            >
                <DashboardCard
                    title="Total Projects"
                    value={projects.length}
                    icon="PR"
                />

                <DashboardCard
                    title="Total Scans"
                    value={totalScans}
                    icon="SC"
                />

                <DashboardCard
                    title="Unique Findings"
                    value={totalFindings ?? "—"}
                    icon="VL"
                />
            </section>

            <section
                className="dashboard__section"
                aria-labelledby="dashboard-severity-title"
            >
                <h2
                    id="dashboard-severity-title"
                    className="dashboard__section-title"
                >
                    Severity Distribution
                </h2>

                {analyticsError ? (
                    <ErrorState
                        message={analyticsError}
                        onRetry={fetchDashboardData}
                    />
                ) : severityCounts === null ? (
                    <LoadingState message="Loading severity analytics..." />
                ) : (
                    <>
                        <p className="dashboard__subtitle">
                            Counts are deduplicated within each scan.
                            The same issue detected in separate scans is
                            counted once per scan.
                        </p>

                        <div className="dashboard__stats">
                            <DashboardCard
                                title="Critical"
                                value={severityCounts.critical}
                                icon="CR"
                            />

                            <DashboardCard
                                title="High"
                                value={severityCounts.high}
                                icon="HI"
                            />

                            <DashboardCard
                                title="Medium"
                                value={severityCounts.medium}
                                icon="ME"
                            />

                            <DashboardCard
                                title="Low"
                                value={severityCounts.low}
                                icon="LO"
                            />
                        </div>

                        <p className="dashboard__meta">
                            Findings in these four severity categories:{" "}
                            {totalSeverityFindings}
                        </p>
                    </>
                )}
            </section>

            <section
                className="dashboard__section"
                aria-labelledby="dashboard-projects-title"
            >
                <h2
                    id="dashboard-projects-title"
                    className="dashboard__section-title"
                >
                    Your Projects
                </h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects yet"
                        message="Create a project to get started."
                    />
                ) : (
                    <div className="dashboard__list">
                        {projects.map((project, index) => (
                            <article
                                key={project.id ?? `project-${index}`}
                                className="dashboard__item"
                            >
                                <h3 className="dashboard__item-title">
                                    {project.name ??
                                        project.project_name ??
                                        `Project ${project.id ?? ""}`}
                                </h3>

                                <p className="dashboard__item-text">
                                    {project.description ||
                                        "No description provided."}
                                </p>

                                <div className="dashboard__meta">
                                    <span>
                                        Project ID:{" "}
                                        {project.id ?? "Not available"}
                                    </span>
                                </div>
                            </article>
                        ))}
                    </div>
                )}

                <div className="dashboard__actions">
                    <button
                        type="button"
                        className="dashboard__button"
                        onClick={() => navigate("/projects")}
                    >
                        View projects
                    </button>

                    <button
                        type="button"
                        className="dashboard__button"
                        onClick={() => navigate("/upload")}
                    >
                        Upload source code
                    </button>
                </div>
            </section>

            <section
                className="dashboard__section"
                aria-labelledby="dashboard-scans-title"
            >
                <h2
                    id="dashboard-scans-title"
                    className="dashboard__section-title"
                >
                    Recent Scans
                </h2>

                {scans.length === 0 ? (
                    <EmptyState
                        title="No scans yet"
                        message="Upload source code and start a scan to see results here."
                    />
                ) : (
                    <div className="dashboard__list">
                        {scans.map((scan, index) => {
                            const scanId = scan.id ?? scan.scan_id;

                            return (
                                <article
                                    key={scanId ?? `scan-${index}`}
                                    className="dashboard__item"
                                >
                                    <h3 className="dashboard__item-title">
                                        Scan #{scanId ?? "N/A"}
                                    </h3>

                                    <span className="dashboard__status">
                                        {scan.status ?? scan.state ?? "Unknown"}
                                    </span>

                                    <div className="dashboard__meta">
                                        <span>
                                            Project ID:{" "}
                                            {scan.project_id ?? "Not available"}
                                        </span>

                                        <span>
                                            Findings:{" "}
                                            {scan.vulnerability_count ?? "Not available"}
                                        </span>

                                        {scan.created_at && (
                                            <span>
                                                Created:{" "}
                                                {new Date(
                                                    scan.created_at
                                                ).toLocaleString()}
                                            </span>
                                        )}
                                    </div>

                                    <div className="dashboard__actions">
                                        <button
                                            type="button"
                                            className="dashboard__button"
                                            disabled={
                                                scanId === null ||
                                                scanId === undefined ||
                                                String(scanId).trim() === ""
                                            }
                                            onClick={() => {
                                                if (
                                                    scanId === null ||
                                                    scanId === undefined ||
                                                    String(scanId).trim() === ""
                                                ) {
                                                    return;
                                                }

                                                navigate("/scan-results", {
                                                    state: {
                                                        scanId,
                                                        result: null,
                                                        projectId: scan.project_id,
                                                    },
                                                });
                                            }}
                                        >
                                            View results
                                        </button>
                                    </div>
                                </article>
                            );
                        })}
                    </div>
                )}
            </section>
        </div>
    );
}

export default Dashboard;
