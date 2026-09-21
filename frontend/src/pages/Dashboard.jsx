import { useEffect, useState } from "react";
import api from "../services/api";

function Dashboard() {
    const [dashboard, setDashboard] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

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
            console.error(
                "Failed to load dashboard:",
                error
            );

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
            </div>
        );
    }

    // =====================================================
    // DATA
    // =====================================================

    const recentScans =
        dashboard.recent_scans || [];

    const vulnerabilityTrend =
        dashboard.vulnerability_trend || [];

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

            <h1>Dashboard</h1>

            <p>
                Overview of your cybersecurity projects
                and vulnerability scans.
            </p>

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
                            {dashboard.critical_vulnerabilities ??
                                0}
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
                            {dashboard.high_vulnerabilities ??
                                0}
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
                            {dashboard.medium_vulnerabilities ??
                                0}
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
                            {dashboard.low_vulnerabilities ??
                                0}
                        </p>
                    </div>
                </div>
            </section>

            {/* ================================================= */}
            {/* VULNERABILITY DISTRIBUTION */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Vulnerability Distribution</h2>

                {(() => {
                    const values = [
                        dashboard.critical_vulnerabilities || 0,
                        dashboard.high_vulnerabilities || 0,
                        dashboard.medium_vulnerabilities || 0,
                        dashboard.low_vulnerabilities || 0,
                    ];

                    const maxValue =
                        Math.max(...values, 1);

                    const data = [
                        {
                            name: "Critical",
                            value:
                                dashboard.critical_vulnerabilities ||
                                0,
                        },
                        {
                            name: "High",
                            value:
                                dashboard.high_vulnerabilities ||
                                0,
                        },
                        {
                            name: "Medium",
                            value:
                                dashboard.medium_vulnerabilities ||
                                0,
                        },
                        {
                            name: "Low",
                            value:
                                dashboard.low_vulnerabilities ||
                                0,
                        },
                    ];

                    return (
                        <div style={{ marginTop: "20px" }}>
                            {data.map((item) => (
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
                                            background:
                                                "#eee",
                                            borderRadius:
                                                "5px",
                                            overflow:
                                                "hidden",
                                        }}
                                    >
                                        <div
                                            style={{
                                                width: `${(item.value / maxValue) * 100}%`,
                                                height: "100%",
                                                background:
                                                    "#555",
                                                borderRadius:
                                                    "5px",
                                            }}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    );
                })()}
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
                                borderCollapse:
                                    "collapse",
                            }}
                        >
                            <thead>
                                <tr>
                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Project
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Date
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Issues Found
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
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
                                        <tr
                                            key={index}
                                        >
                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    scan.project
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    scan.date
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    scan.issues_found
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    scan.status
                                                }
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
                                borderCollapse:
                                    "collapse",
                            }}
                        >
                            <thead>
                                <tr>
                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Date
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Critical
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        High
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
                                            borderBottom:
                                                "1px solid #ccc",
                                        }}
                                    >
                                        Medium
                                    </th>

                                    <th
                                        style={{
                                            textAlign:
                                                "left",
                                            padding:
                                                "10px",
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
                                        <tr
                                            key={index}
                                        >
                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    item.date
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    item.critical
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    item.high
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    item.medium
                                                }
                                            </td>

                                            <td
                                                style={{
                                                    padding:
                                                        "10px",
                                                    borderBottom:
                                                        "1px solid #eee",
                                                }}
                                            >
                                                {
                                                    item.low
                                                }
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
                }}
            >
                <button
                    type="button"
                    onClick={fetchDashboard}
                >
                    Refresh Dashboard
                </button>
            </div>
        </div>
    );
}

export default Dashboard;