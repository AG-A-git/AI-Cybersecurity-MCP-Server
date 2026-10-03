import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    getProjects,
    getProjectFiles,
} from "../services/projectService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function Reports() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const fetchReport = async () => {
        try {
            setLoading(true);
            setError("");

            const projectsResponse =
                await getProjects();

            const projectList =
                Array.isArray(projectsResponse.data)
                    ? projectsResponse.data
                    : [];

            const projectReports =
                await Promise.all(
                    projectList.map(
                        async (project) => {
                            try {
                                const filesResponse =
                                    await getProjectFiles(
                                        project.id
                                    );

                                const files =
                                    Array.isArray(
                                        filesResponse.data
                                    )
                                        ? filesResponse.data
                                        : [];

                                return {
                                    ...project,
                                    files,
                                    total_files:
                                        files.length,
                                };
                            } catch (err) {
                                console.error(
                                    `Failed to load files for project ${project.id}:`,
                                    err
                                );

                                return {
                                    ...project,
                                    files: [],
                                    total_files: 0,
                                };
                            }
                        }
                    )
                );

            setProjects(projectReports);
        } catch (error) {
            console.error(
                "Failed to fetch report data:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Failed to load report data."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchReport();
    }, []);

    const totalFiles = projects.reduce(
        (total, project) =>
            total + project.total_files,
        0
    );

    if (loading) {
        return (
            <div
                style={{
                    padding: "30px",
                }}
            >
                <h1>Reports</h1>

                <LoadingState
                    message="Loading project report..."
                />
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
                    onRetry={fetchReport}
                />
            </div>
        );
    }

    if (projects.length === 0) {
        return (
            <div
                style={{
                    padding: "30px",
                    maxWidth: "1000px",
                    margin: "0 auto",
                }}
            >
                <h1>Reports</h1>

                <EmptyState
                    title="No project data"
                    message="Create a project and upload a file to generate report data."
                    buttonText="Go to Projects"
                    onButtonClick={() =>
                        navigate("/projects")
                    }
                />
            </div>
        );
    }

    return (
        <div
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            <h1>Project & Upload Summary</h1>

            <p>
                View a summary of your projects
                and uploaded source files.
            </p>

            <hr />

            {/* SUMMARY */}

            <section
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(200px, 1fr))",
                    gap: "20px",
                    marginTop: "30px",
                }}
            >
                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>
                        Total Projects
                    </h3>

                    <p
                        style={{
                            fontSize: "32px",
                            fontWeight: "bold",
                        }}
                    >
                        {projects.length}
                    </p>
                </div>

                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>
                        Total Uploaded Files
                    </h3>

                    <p
                        style={{
                            fontSize: "32px",
                            fontWeight: "bold",
                        }}
                    >
                        {totalFiles}
                    </p>
                </div>
            </section>

            {/* PROJECT REPORTS */}

            <section
                style={{
                    marginTop: "35px",
                }}
            >
                <h2>
                    Project Reports
                </h2>

                <div
                    style={{
                        marginTop: "20px",
                    }}
                >
                    {projects.map(
                        (project) => (
                            <div
                                key={project.id}
                                style={{
                                    border:
                                        "1px solid #ccc",
                                    borderRadius:
                                        "8px",
                                    padding:
                                        "20px",
                                    marginBottom:
                                        "20px",
                                }}
                            >
                                <h3>
                                    {
                                        project.name
                                    }
                                </h3>

                                <p>
                                    <strong>
                                        Project ID:
                                    </strong>{" "}
                                    {
                                        project.id
                                    }
                                </p>

                                <p>
                                    <strong>
                                        Description:
                                    </strong>{" "}
                                    {project.description ||
                                        "No description"}
                                </p>

                                <p>
                                    <strong>
                                        Files:
                                    </strong>{" "}
                                    {
                                        project.total_files
                                    }
                                </p>

                                {project.files
                                    .length ===
                                0 ? (
                                    <EmptyState
                                        title="No files"
                                        message="No files have been uploaded for this project."
                                    />
                                ) : (
                                    <table
                                        style={{
                                            width:
                                                "100%",
                                            borderCollapse:
                                                "collapse",
                                            marginTop:
                                                "15px",
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
                                                            "2px solid #ccc",
                                                    }}
                                                >
                                                    File
                                                </th>

                                                <th
                                                    style={{
                                                        textAlign:
                                                            "left",
                                                        padding:
                                                            "10px",
                                                        borderBottom:
                                                            "2px solid #ccc",
                                                    }}
                                                >
                                                    Uploaded
                                                </th>
                                            </tr>
                                        </thead>

                                        <tbody>
                                            {project.files.map(
                                                (
                                                    file
                                                ) => (
                                                    <tr
                                                        key={
                                                            file.id
                                                        }
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
                                                                file.filename
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
                                                            {file.uploaded_at
                                                                ? new Date(
                                                                    file.uploaded_at
                                                                ).toLocaleString()
                                                                : "N/A"}
                                                        </td>
                                                    </tr>
                                                )
                                            )}
                                        </tbody>
                                    </table>
                                )}

                                <button
                                    type="button"
                                    style={{
                                        marginTop:
                                            "15px",
                                    }}
                                    onClick={() => {
                                        localStorage.setItem(
                                            "selected_project_id",
                                            String(
                                                project.id
                                            )
                                        );

                                        navigate(
                                            "/upload"
                                        );
                                    }}
                                >
                                    Open Project
                                </button>
                            </div>
                        )
                    )}
                </div>
            </section>

            {/* ACTIONS */}

            <div
                style={{
                    display: "flex",
                    gap: "10px",
                    marginTop: "30px",
                }}
            >
                <button
                    type="button"
                    onClick={fetchReport}
                >
                    Refresh Data
                </button>

                <button
                    type="button"
                    onClick={() =>
                        navigate(
                            "/projects"
                        )
                    }
                >
                    Back to Projects
                </button>

                <button
                    type="button"
                    onClick={() =>
                        navigate(
                            "/dashboard"
                        )
                    }
                >
                    Back to Dashboard
                </button>
            </div>
        </div>
    );
}

export default Reports;
