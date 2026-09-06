import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../services/api";

function Dashboard() {
    const navigate = useNavigate();

    const [dashboardData, setDashboardData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const fetchDashboard = async () => {
            try {
                const response = await api.get("/dashboard");

                console.log("Dashboard data:", response.data);

                setDashboardData(response.data);
            } catch (error) {
                console.error(
                    "Dashboard loading failed:",
                    error
                );

                if (error.response?.status === 401) {
                    setError(
                        "Session expired. Please login again."
                    );

                    localStorage.removeItem(
                        "access_token"
                    );

                    navigate("/login");
                } else {
                    setError(
                        error.response?.data?.detail ||
                        "Failed to load dashboard data."
                    );
                }
            } finally {
                setLoading(false);
            }
        };

        fetchDashboard();
    }, [navigate]);

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        navigate("/login");
    };

    return (
        <div>
            <h1>Dashboard</h1>

            <p>
                Welcome to the AI Cybersecurity Dashboard.
            </p>

            {/* Navigation */}
            <nav>
                <ul>
                    <li>
                        <Link to="/dashboard">
                            Dashboard
                        </Link>
                    </li>

                    <li>
                        <Link to="/projects">
                            Projects
                        </Link>
                    </li>

                    <li>
                        <Link to="/upload">
                            Upload & Scan
                        </Link>
                    </li>

                    <li>
                        <Link to="/history">
                            History
                        </Link>
                    </li>

                    <li>
                        <Link to="/reports">
                            Reports
                        </Link>
                    </li>

                    <li>
                        <Link to="/profile">
                            Profile
                        </Link>
                    </li>

                    <li>
                        <button onClick={handleLogout}>
                            Logout
                        </button>
                    </li>
                </ul>
            </nav>

            <hr />

            <h2>Security Dashboard</h2>

            {/* Loading */}
            {loading && (
                <p>
                    Loading dashboard...
                </p>
            )}

            {/* Error */}
            {error && (
                <p style={{ color: "red" }}>
                    {error}
                </p>
            )}

            {/* Dashboard Data */}
            {!loading &&
                !error &&
                dashboardData && (
                    <div>
                        {/* Statistics */}
                        <h3>Security Statistics</h3>

                        <div>
                            <div>
                                <h4>Total Projects</h4>
                                <p>
                                    {
                                        dashboardData.total_projects
                                    }
                                </p>
                            </div>

                            <div>
                                <h4>Total Scans</h4>
                                <p>
                                    {
                                        dashboardData.total_scans
                                    }
                                </p>
                            </div>

                            <div>
                                <h4>Critical</h4>
                                <p>
                                    {
                                        dashboardData.critical_vulnerabilities
                                    }
                                </p>
                            </div>

                            <div>
                                <h4>High</h4>
                                <p>
                                    {
                                        dashboardData.high_vulnerabilities
                                    }
                                </p>
                            </div>

                            <div>
                                <h4>Medium</h4>
                                <p>
                                    {
                                        dashboardData.medium_vulnerabilities
                                    }
                                </p>
                            </div>

                            <div>
                                <h4>Low</h4>
                                <p>
                                    {
                                        dashboardData.low_vulnerabilities
                                    }
                                </p>
                            </div>
                        </div>

                        <hr />

                        {/* Recent Scans */}
                        <h3>Recent Scans</h3>

                        {dashboardData.recent_scans &&
                        dashboardData.recent_scans.length > 0 ? (
                            <table border="1" cellPadding="10">
                                <thead>
                                    <tr>
                                        <th>Project</th>
                                        <th>Date</th>
                                        <th>Issues Found</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {dashboardData.recent_scans.map(
                                        (scan, index) => (
                                            <tr key={index}>
                                                <td>
                                                    {scan.project}
                                                </td>

                                                <td>
                                                    {scan.date}
                                                </td>

                                                <td>
                                                    {
                                                        scan.issues_found
                                                    }
                                                </td>

                                                <td>
                                                    {scan.status}
                                                </td>
                                            </tr>
                                        )
                                    )}
                                </tbody>
                            </table>
                        ) : (
                            <p>
                                No recent scans available.
                            </p>
                        )}

                        <hr />

                        {/* Vulnerability Trend */}
                        <h3>
                            Vulnerability Trend
                        </h3>

                        {dashboardData.vulnerability_trend &&
                        dashboardData.vulnerability_trend.length > 0 ? (
                            <table border="1" cellPadding="10">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Critical</th>
                                        <th>High</th>
                                        <th>Medium</th>
                                        <th>Low</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {dashboardData.vulnerability_trend.map(
                                        (item, index) => (
                                            <tr key={index}>
                                                <td>
                                                    {item.date}
                                                </td>

                                                <td>
                                                    {item.critical}
                                                </td>

                                                <td>
                                                    {item.high}
                                                </td>

                                                <td>
                                                    {item.medium}
                                                </td>

                                                <td>
                                                    {item.low}
                                                </td>
                                            </tr>
                                        )
                                    )}
                                </tbody>
                            </table>
                        ) : (
                            <p>
                                No vulnerability trend data
                                available.
                            </p>
                        )}
                    </div>
                )}
        </div>
    );
}

export default Dashboard;