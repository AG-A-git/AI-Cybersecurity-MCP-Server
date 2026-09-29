import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Dashboard() {
    const [dashboard, setDashboard] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const navigate = useNavigate();

    // =====================================================
    // LOGOUT
    // =====================================================

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        navigate("/login");
    };

    // =====================================================
    // FETCH DASHBOARD DATA
    // =====================================================

    const fetchDashboard = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await api.get("/dashboard");

            console.log("Dashboard data:", response.data);

            setDashboard(response.data);
        } catch (error) {
            console.error("Failed to load dashboard:", error);

            setError(
                error.userMessage ||
                error.response?.data?.detail ||
                "Failed to load dashboard."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDashboard();
    }, []);

    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <p>Loading dashboard...</p>
            </div>
        );
    }

    // =====================================================
    // ERROR
    // =====================================================

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>

                <p style={{ color: "red" }}>
                    {error}
                </p>

                <button
                    type="button"
                    onClick={fetchDashboard}
                >
                    Try Again
                </button>

                <button
                    type="button"
                    onClick={handleLogout}
                    style={{ marginLeft: "10px" }}
                >
                    Logout
                </button>
            </div>
        );
    }

    // =====================================================
    // NO DATA
    // =====================================================

    if (!dashboard) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Dashboard</h1>
                <p>No dashboard data available.</p>

                <button
                    type="button"
                    onClick={handleLogout}
                >
                    Logout
                </button>
            </div>
        );
    }

    // =====================================================
    // REAL BACKEND DATA
    // =====================================================

    const critical =
        dashboard.critical_vulnerabilities ?? 0;

    const high =
        dashboard.high_vulnerabilities ?? 0;

    const medium =
        dashboard.medium_vulnerabilities ?? 0;

    const low =
        dashboard.low_vulnerabilities ?? 0;

    const totalVulnerabilities =
        critical + high + medium + low;

    const recentScans =
        dashboard.recent_scans || [];

    const vulnerabilityTrend =
        dashboard.vulnerability_trend || [];

    // =====================================================
    // SEVERITY DATA
    // =====================================================

    const severityData = [
        {
            name: "Critical",
            value: critical,
        },
        {
            name: "High",
            value: high,
        },
        {
            name: "Medium",
            value: medium,
        },
        {
            name: "Low",
            value: low,
        },
    ];

    const maxSeverityValue =
        Math.max(
            ...severityData.map((item) => item.value),
            1
        );

    // =====================================================
    // RENDER
    // =====================================================

    return (
        <div
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                }}
            >
                <div>
                    <h1>Dashboard</h1>

                    <p>
                        Overview of your cybersecurity projects
                        and vulnerability scans.
                    </p>
                </div>

                <button
                    type="button"
                    onClick={handleLogout}
                >
                    Logout
                </button>
            </div>

            <hr />

            {/* ================================================= */}
            {/* SUMMARY CARDS */}
            {/* ================================================= */}

            <section style={{ marginTop: "25px" }}>
                <h2>Security Overview</h2>

                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: "15px",
                    }}
                >
                    {/* PROJECTS */}

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
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {dashboard.total_projects ?? 0}
                        </p>
                    </div>

                    {/* SCANS */}

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
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {dashboard.total_scans ?? 0}
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
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {totalVulnerabilities}
                        </p>
                    </div>

                    {/* CRITICAL */}

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Critical</h3>

                        <p
                            style={{
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {critical}
                        </p>
                    </div>

                    {/* HIGH */}

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>High</h3>

                        <p
                            style={{
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {high}
                        </p>
                    </div>

                    {/* MEDIUM */}

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Medium</h3>

                        <p
                            style={{
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {medium}
                        </p>
                    </div>

                    {/* LOW */}

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Low</h3>

                        <p
                            style={{
                                fontSize: "30px",
                                fontWeight: "bold",
                            }}
                        >
                            {low}
                        </p>
                    </div>
                </div>
            </section>

            {/* ================================================= */}
            {/* SEVERITY DISTRIBUTION */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Severity Distribution</h2>

                {totalVulnerabilities === 0 ? (
                    <p>No vulnerabilities found.</p>
                ) : (
                    <div style={{ marginTop: "20px" }}>
                        {severityData.map((item) => (
                            <div
                                key={item.name}
                                style={{
                                    marginBottom: "18px",
                                }}
                            >
                                <div
                                    style={{
                                        display: "flex",
                                        justifyContent:
                                            "space-between",
                                        marginBottom: "5px",
                                    }}
                                >
                                    <strong>
                                        {item.name}
                                    </strong>

                                    <span>
                                        {item.value}
                                    </span>
                                </div>

                                <div
                                    style={{
                                        width: "100%",
                                        height: "25px",
                                        background: "#eee",
                                        borderRadius: "5px",
                                        overflow: "hidden",
                                    }}
                                >
                                    <div
                                        style={{
                                            width: `${
                                                (item.value /
                                                    maxSeverityValue) *
                                                100
                                            }%`,
                                            height: "100%",
                                            background: "#555",
                                            borderRadius: "5px",
                                        }}
                                    />
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </section>

            {/* ================================================= */}
            {/* RISK OVERVIEW */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Risk Overview</h2>

                <p>
                    Current vulnerability counts grouped by
                    backend-provided severity.
                </p>

                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: "15px",
                        marginTop: "20px",
                    }}
                >
                    <div>
                        <strong>Critical Risk</strong>
                        <p>{critical}</p>
                    </div>

                    <div>
                        <strong>High Risk</strong>
                        <p>{high}</p>
                    </div>

                    <div>
                        <strong>Medium Risk</strong>
                        <p>{medium}</p>
                    </div>

                    <div>
                        <strong>Low Risk</strong>
                        <p>{low}</p>
                    </div>
                </div>
            </section>

            {/* ================================================= */}
            {/* RECENT SCANS */}
            {/* ================================================= */}

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
                    <p>No recent scans found.</p>
                ) : (
                    <div
                        style={{
                            overflowX: "auto",
                        }}
                    >
                        <table
                            style={{
                                width: "100%",
                                borderCollapse: "collapse",
                            }}
                        >
                            <thead>
                                <tr>
                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Project
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Date
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Issues Found
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Status
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {recentScans.map(
                                    (scan, index) => (
                                        <tr key={index}>
                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {scan.project}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {scan.date}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {scan.issues_found}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {scan.status}
                                            </td>
                                        </tr>
                                    )
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>

            {/* ================================================= */}
            {/* VULNERABILITY TREND */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Vulnerability Trend</h2>

                {vulnerabilityTrend.length === 0 ? (
                    <p>
                        No vulnerability trend data
                        available.
                    </p>
                ) : (
                    <div
                        style={{
                            overflowX: "auto",
                        }}
                    >
                        <table
                            style={{
                                width: "100%",
                                borderCollapse: "collapse",
                            }}
                        >
                            <thead>
                                <tr>
                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Date
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Critical
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        High
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Medium
                                    </th>

                                    <th
                                        style={{
                                            textAlign: "left",
                                            padding: "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Low
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {vulnerabilityTrend.map(
                                    (item, index) => (
                                        <tr key={index}>
                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {item.date}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {item.critical ?? 0}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {item.high ?? 0}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {item.medium ?? 0}
                                            </td>

                                            <td
                                                style={{
                                                    padding: "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {item.low ?? 0}
                                            </td>
                                        </tr>
                                    )
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>

            {/* ================================================= */}
            {/* REFRESH */}
            {/* ================================================= */}

            <div
                style={{
                    marginTop: "30px",
                    display: "flex",
                    gap: "10px",
                }}
            >
                <button
                    type="button"
                    onClick={fetchDashboard}
                >
                    Refresh Dashboard
                </button>

                <button
                    type="button"
                    onClick={handleLogout}
                >
                    Logout
                </button>
            </div>
        </div>
    );
}

export default Dashboard;