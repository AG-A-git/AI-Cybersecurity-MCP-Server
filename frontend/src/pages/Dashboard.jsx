import { useEffect, useState } from "react";
import { getDashboard } from "../services/dashboardService";

function Dashboard() {
    const [dashboard, setDashboard] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const loadDashboard = async () => {
            try {
                setLoading(true);
                setError("");

                const response = await getDashboard();

                setDashboard(response.data);
            } catch (err) {
                console.error("Dashboard error:", err);

                setError(
                    err.userMessage ||
                    "Unable to load dashboard."
                );
            } finally {
                setLoading(false);
            }
        };

        loadDashboard();
    }, []);

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <p>Loading dashboard...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>

                <p style={{ color: "red" }}>
                    {error}
                </p>
            </div>
        );
    }

    if (!dashboard) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <p>No dashboard data available.</p>
            </div>
        );
    }

    // =====================================================
    // PROJECTS AND SCANS
    // =====================================================

    const totalProjects =
        dashboard.total_projects ?? 0;

    const totalScans =
        dashboard.total_scans ?? 0;

    // =====================================================
    // VULNERABILITY COUNTS
    // =====================================================

    const critical =
        dashboard.critical_vulnerabilities;

    const high =
        dashboard.high_vulnerabilities;

    const medium =
        dashboard.medium_vulnerabilities;

    const low =
        dashboard.low_vulnerabilities;

    // =====================================================
    // CHECK WHETHER VULNERABILITY DATA EXISTS
    // =====================================================

    const vulnerabilityDataAvailable =
        critical !== null &&
        high !== null &&
        medium !== null &&
        low !== null;

    // =====================================================
    // TOTAL VULNERABILITIES
    // =====================================================

    const totalVulnerabilities =
        vulnerabilityDataAvailable
            ? critical + high + medium + low
            : null;

    // =====================================================
    // RECENT SCANS
    // =====================================================

    const recentScans =
        dashboard.recent_scans ?? [];

    return (
        <div
            style={{
                padding: "30px",
            }}
        >
            <h1>Dashboard</h1>

            <p>
                Overview of your cybersecurity
                projects and scans.
            </p>

            {/* =================================================
                MAIN STATISTICS
            ================================================= */}

            <section
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: "15px",
                    marginTop: "25px",
                }}
            >
                {/* TOTAL PROJECTS */}

                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>Total Projects</h3>

                    <p
                        style={{
                            fontSize: "28px",
                            fontWeight: "bold",
                        }}
                    >
                        {totalProjects}
                    </p>
                </div>

                {/* TOTAL SCANS */}

                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>Total Scans</h3>

                    <p
                        style={{
                            fontSize: "28px",
                            fontWeight: "bold",
                        }}
                    >
                        {totalScans}
                    </p>
                </div>

                {/* TOTAL VULNERABILITIES */}

                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>Total Vulnerabilities</h3>

                    <p
                        style={{
                            fontSize: "28px",
                            fontWeight: "bold",
                        }}
                    >
                        {totalVulnerabilities ??
                            "Not available"}
                    </p>
                </div>
            </section>

            {/* =================================================
                VULNERABILITY SUMMARY
            ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Vulnerability Summary</h2>

                {!vulnerabilityDataAvailable ? (
                    <p>
                        Vulnerability statistics are not
                        available yet because scan findings
                        are not currently stored in the
                        backend database.
                    </p>
                ) : (
                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns:
                                "repeat(auto-fit, minmax(150px, 1fr))",
                            gap: "15px",
                        }}
                    >
                        <div>
                            <strong>Critical</strong>
                            <p>{critical}</p>
                        </div>

                        <div>
                            <strong>High</strong>
                            <p>{high}</p>
                        </div>

                        <div>
                            <strong>Medium</strong>
                            <p>{medium}</p>
                        </div>

                        <div>
                            <strong>Low</strong>
                            <p>{low}</p>
                        </div>
                    </div>
                )}
            </section>

            {/* =================================================
                RECENT SCANS
            ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Recent Scans</h2>

                {recentScans.length === 0 ? (
                    <p>
                        No scans available yet.
                    </p>
                ) : (
                    <div>
                        {recentScans.map(
                            (scan, index) => (
                                <div
                                    key={
                                        scan.id ??
                                        `${scan.project}-${index}`
                                    }
                                    style={{
                                        borderBottom:
                                            "1px solid #ddd",
                                        padding:
                                            "15px 0",
                                    }}
                                >
                                    <h3>
                                        {scan.project ||
                                            "Unknown Project"}
                                    </h3>

                                    <p>
                                        <strong>
                                            Date:
                                        </strong>{" "}
                                        {scan.date ||
                                            "Not available"}
                                    </p>

                                    <p>
                                        <strong>
                                            Issues Found:
                                        </strong>{" "}
                                        {scan.issues_found ??
                                            "Not available"}
                                    </p>

                                    <p>
                                        <strong>
                                            Status:
                                        </strong>{" "}
                                        {scan.status ||
                                            "Not available"}
                                    </p>
                                </div>
                            )
                        )}
                    </div>
                )}
            </section>
        </div>
    );
}

export default Dashboard;