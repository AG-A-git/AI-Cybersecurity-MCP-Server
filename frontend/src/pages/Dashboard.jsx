import { useEffect, useState } from "react";

import {
    getProjects,
    getProjectFiles,
} from "../services/projectService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import DashboardCard from "../components/DashboardCard";

function Dashboard() {
    const [projects, setProjects] = useState([]);
    const [totalFiles, setTotalFiles] = useState(0);

    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const fetchDashboardData = async () => {
        try {
            setLoading(true);
            setError("");

            const projectsResponse =
                await getProjects();

            const projectList =
                Array.isArray(
                    projectsResponse.data
                )
                    ? projectsResponse.data
                    : [];

            setProjects(projectList);

            const fileResults =
                await Promise.all(
                    projectList.map(
                        async (project) => {
                            try {
                                const response =
                                    await getProjectFiles(
                                        project.id
                                    );

                                return Array.isArray(
                                    response.data
                                )
                                    ? response.data
                                    : [];
                            } catch (err) {
                                console.error(
                                    `Failed to load files for project ${project.id}:`,
                                    err
                                );

                                return [];
                            }
                        }
                    )
                );

            const fileCount =
                fileResults.reduce(
                    (
                        total,
                        files
                    ) =>
                        total +
                        files.length,
                    0
                );

            setTotalFiles(
                fileCount
            );
        } catch (error) {
            console.error(
                "Dashboard error:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Unable to load dashboard."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDashboardData();
    }, []);

    if (loading) {
        return (
            <div
                style={{
                    padding: "30px",
                }}
            >
                <h1>Dashboard</h1>

                <LoadingState
                    message="Loading dashboard..."
                />
            </div>
        );
    }

    if (error) {
        return (
            <div
                style={{
                    padding: "30px",
                }}
            >
                <h1>Dashboard</h1>

                <ErrorState
                    message={error}
                    onRetry={
                        fetchDashboardData
                    }
                />
            </div>
        );
    }

    return (
        <div
            style={{
                padding: "30px",
            }}
        >
            <h1>Dashboard</h1>

            <p>
                Overview of your cybersecurity
                projects.
            </p>

            <section
                className="row g-3"
                style={{
                    marginTop: "25px",
                }}
            >
                <div className="col-md-6">
                    <DashboardCard
                        title="Total Projects"
                        value={
                            projects.length
                        }
                        icon="📁"
                    />
                </div>

                <div className="col-md-6">
                    <DashboardCard
                        title="Uploaded Files"
                        value={
                            totalFiles
                        }
                        icon="📄"
                    />
                </div>
            </section>

            <section
                style={{
                    marginTop: "30px",
                    border:
                        "1px solid #ccc",
                    borderRadius:
                        "8px",
                    padding: "20px",
                }}
            >
                <h2>
                    Your Projects
                </h2>

                {projects.length ===
                0 ? (
                    <EmptyState
                        title="No projects yet"
                        message="Create your first project to start uploading source code."
                    />
                ) : (
                    <div>
                        {projects.map(
                            (project) => (
                                <div
                                    key={
                                        project.id
                                    }
                                    style={{
                                        borderBottom:
                                            "1px solid #ddd",
                                        padding:
                                            "15px 0",
                                    }}
                                >
                                    <h3>
                                        {
                                            project.name
                                        }
                                    </h3>

                                    <p>
                                        {
                                            project.description ||
                                            "No description provided."
                                        }
                                    </p>

                                    <p>
                                        <strong>
                                            Project ID:
                                        </strong>{" "}
                                        {
                                            project.id
                                        }
                                    </p>
                                </div>
                            )
                        )}
                    </div>
                )}
            </section>

            <section
                style={{
                    marginTop: "30px",
                    border:
                        "1px solid #ccc",
                    borderRadius:
                        "8px",
                    padding: "20px",
                }}
            >
                <h2>
                    Scan Information
                </h2>

                <p>
                    Scan and vulnerability
                    statistics will appear
                    here once the backend
                    scanner APIs are available.
                </p>
            </section>

            <div
                style={{
                    marginTop: "25px",
                }}
            >
                <button
                    type="button"
                    onClick={
                        fetchDashboardData
                    }
                >
                    Refresh Dashboard
                </button>
            </div>
        </div>
    );
}

export default Dashboard;