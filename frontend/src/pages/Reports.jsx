import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function Reports() {
    const navigate = useNavigate();

    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    // =====================================================
    // FETCH REPORT
    // =====================================================

    const fetchReport = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await api.get("/reports");

            console.log(
                "Security report:",
                response.data
            );

            setReport(response.data);
        } catch (error) {
            console.error(
                "Failed to fetch report:",
                error
            );

            setError(
                error.userMessage ||
                error.response?.data?.detail ||
                "Failed to load report."
            );
        } finally {
            setLoading(false);
        }
    };

    // =====================================================
    // INITIAL LOAD
    // =====================================================

    useEffect(() => {
        fetchReport();
    }, []);

    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Reports</h1>

                <LoadingState
                    message="Loading security report..."
                />
            </div>
        );
    }

    // =====================================================
    // ERROR
    // =====================================================

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

    // =====================================================
    // EMPTY REPORT
    // =====================================================

    if (
        !report ||
        (
            report.total_projects === 0 &&
            report.total_files === 0
        )
    ) {
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
                    title="No report data"
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
            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <h1>Security Reports</h1>

            <p>
                View a summary of your projects
                and uploaded files.
            </p>

            <hr />

            {/* ================================================= */}
            {/* SUMMARY */}
            {/* ================================================= */}

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
                    <h3>Total Projects</h3>

                    <p
                        style={{
                            fontSize: "32px",
                            fontWeight: "bold",
                        }}
                    >
                        {report.total_projects}
                    </p>
                </div>

                <div
                    style={{
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h3>Total Scanned Files</h3>

                    <p
                        style={{
                            fontSize: "32px",
                            fontWeight: "bold",
                        }}
                    >
                        {report.total_files}
                    </p>
                </div>
            </section>

            {/* ================================================= */}
            {/* PROJECT REPORTS */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "35px",
                }}
            >
                <h2>Project Reports</h2>

                {report.projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create a project and upload a file to generate report data."
                        buttonText="Go to Projects"
                        onButtonClick={() =>
                            navigate("/projects")
                        }
                    />
                ) : (
                    <div
                        style={{
                            marginTop: "20px",
                        }}
                    >
                        {report.projects.map(
                            (project) => (
                                <div
                                    key={
                                        project.project_id
                                    }
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
                                            project.project_name
                                        }
                                    </h3>

                                    <p>
                                        <strong>
                                            Project ID:
                                        </strong>{" "}
                                        {
                                            project.project_id
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
                                        .length === 0 ? (
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
                                                        Status
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
                                                                {
                                                                    file.status
                                                                }
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
                                                project.project_id
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
                )}
            </section>

            {/* ================================================= */}
            {/* ACTIONS */}
            {/* ================================================= */}

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
                    Refresh Report
                </button>

                <button
                    type="button"
                    onClick={() =>
                        navigate("/projects")
                    }
                >
                    Back to Projects
                </button>

                <button
                    type="button"
                    onClick={() =>
                        navigate("/dashboard")
                    }
                >
                    Back to Dashboard
                </button>
            </div>
        </div>
    );
}

export default Reports;