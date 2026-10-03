import { useEffect, useState } from "react";

import {
    getProjects,
    getProjectFiles,
} from "../services/projectService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function History() {
    const [files, setFiles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const loadHistory = async () => {
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

            const fileResults =
                await Promise.all(
                    projectList.map(
                        async (project) => {
                            try {
                                const response =
                                    await getProjectFiles(
                                        project.id
                                    );

                                return (
                                    response.data ||
                                    []
                                ).map(
                                    (file) => ({
                                        ...file,
                                        project_name:
                                            project.name,
                                    })
                                );
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

            setFiles(
                fileResults.flat()
            );
        } catch (err) {
            console.error(
                "Upload history error:",
                err
            );

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    "Unable to load upload history."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadHistory();
    }, []);

    if (loading) {
        return (
            <div
                style={{
                    padding: "30px",
                }}
            >
                <h1>Upload History</h1>

                <LoadingState
                    message="Loading upload history..."
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
                <h1>Upload History</h1>

                <ErrorState
                    message={error}
                    onRetry={loadHistory}
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
            <h1>Upload History</h1>

            <p>
                View source files uploaded to
                your cybersecurity projects.
            </p>

            {files.length === 0 ? (
                <EmptyState
                    title="No uploads yet"
                    message="Upload a source file from a project to see it here."
                />
            ) : (
                <div
                    style={{
                        marginTop: "25px",
                        display: "grid",
                        gap: "15px",
                    }}
                >
                    {files.map(
                        (file) => (
                            <div
                                key={
                                    file.id
                                }
                                style={{
                                    border:
                                        "1px solid #ccc",
                                    borderRadius:
                                        "8px",
                                    padding:
                                        "20px",
                                }}
                            >
                                <h2>
                                    {
                                        file.project_name
                                    }
                                </h2>

                                <p>
                                    <strong>
                                        File:
                                    </strong>{" "}
                                    {
                                        file.filename
                                    }
                                </p>

                                <p>
                                    <strong>
                                        File ID:
                                    </strong>{" "}
                                    {
                                        file.id
                                    }
                                </p>

                                <p>
                                    <strong>
                                        Project ID:
                                    </strong>{" "}
                                    {
                                        file.project_id
                                    }
                                </p>

                                <p>
                                    <strong>
                                        Uploaded:
                                    </strong>{" "}
                                    {file.uploaded_at
                                        ? new Date(
                                            file.uploaded_at
                                        ).toLocaleString()
                                        : "N/A"}
                                </p>

                                <p>
                                    <strong>
                                        Status:
                                    </strong>{" "}
                                    Uploaded
                                </p>
                            </div>
                        )
                    )}
                </div>
            )}
        </div>
    );
}

export default History;