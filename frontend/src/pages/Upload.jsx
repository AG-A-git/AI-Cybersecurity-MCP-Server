import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import LoadingState from "../components/LoadingState";
import EmptyState from "../components/EmptyState";

function Upload() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);

    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingUpload, setLoadingUpload] = useState(false);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    // Fetch projects
    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const response = await api.get("/projects/");

            console.log("Projects:", response.data);

            setProjects(response.data);

            // Restore previously selected project
            const selectedProjectId =
                localStorage.getItem("selected_project_id");

            if (selectedProjectId) {
                const selectedProjectExists =
                    response.data.some(
                        (project) =>
                            String(project.id) ===
                            String(selectedProjectId)
                    );

                if (selectedProjectExists) {
                    setProjectId(selectedProjectId);
                }
            }
        } catch (error) {
            console.error(
                "Failed to load projects:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Failed to load projects."
            );
        } finally {
            setLoadingProjects(false);
        }
    };

    useEffect(() => {
        fetchProjects();
    }, []);

    // Project selection
    const handleProjectChange = (e) => {
        const selectedId = e.target.value;

        setProjectId(selectedId);

        if (selectedId) {
            localStorage.setItem(
                "selected_project_id",
                selectedId
            );
        } else {
            localStorage.removeItem(
                "selected_project_id"
            );
        }

        setError("");
        setSuccess("");
    };

    // File selection
    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];

        setFile(selectedFile || null);
        setError("");
        setSuccess("");
    };

    // Upload and scan
    const handleUpload = async (e) => {
        e.preventDefault();

        setError("");
        setSuccess("");

        // Validate project
        if (!projectId) {
            setError("Please select a project.");
            return;
        }

        // Validate file
        if (!file) {
            setError("Please select a file.");
            return;
        }

        // Maximum file size: 5 MB
        const maxSize = 5 * 1024 * 1024;

        if (file.size > maxSize) {
            setError(
                "File is too large. Maximum size is 5 MB."
            );
            return;
        }

        setLoadingUpload(true);

        try {
            // Save selected project
            localStorage.setItem(
                "selected_project_id",
                String(projectId)
            );

            // Create multipart form data
            const formData = new FormData();

            formData.append(
                "project_id",
                String(projectId)
            );

            formData.append("file", file);

            console.log(
                "Sending project_id:",
                projectId
            );

            console.log(
                "Sending file:",
                file.name
            );

            // Call backend upload API
            const response = await api.post(
                "/upload",
                formData
            );

            console.log(
                "Upload response:",
                response.data
            );

            setSuccess(
                "Security scan completed!"
            );

            // Navigate to scan results
            navigate("/scan-results", {
                state: {
                    result: response.data,
                    projectId: projectId,
                },
            });
        } catch (error) {
            console.error(
                "Upload failed:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Upload failed. Please try again."
            );
        } finally {
            setLoadingUpload(false);
        }
    };

    return (
        <div style={{ padding: "30px" }}>
            <h1>Upload Source Code</h1>

            <p>
                Select a project and upload source
                code for security scanning.
            </p>

            <hr />

            <form onSubmit={handleUpload}>
                {/* PROJECT SECTION */}
                <div>
                    <label htmlFor="project">
                        <strong>
                            Select Project
                        </strong>
                    </label>

                    <br />
                    <br />

                    {/* Loading projects */}
                    {loadingProjects ? (
                        <LoadingState
                            message="Loading projects..."
                        />
                    ) : projects.length === 0 ? (
                        /* No projects */
                        <EmptyState
                            title="No projects found"
                            message="Please create a project before uploading source code."
                            buttonText="Go to Projects"
                            onButtonClick={() =>
                                navigate("/projects")
                            }
                        />
                    ) : (
                        /* Project dropdown */
                        <select
                            id="project"
                            value={projectId}
                            onChange={
                                handleProjectChange
                            }
                        >
                            <option value="">
                                -- Select Project --
                            </option>

                            {projects.map(
                                (project) => (
                                    <option
                                        key={project.id}
                                        value={project.id}
                                    >
                                        {project.name}
                                    </option>
                                )
                            )}
                        </select>
                    )}
                </div>

                <br />

                {/* SELECTED PROJECT */}
                {projectId && (
                    <p>
                        <strong>
                            Selected Project ID:
                        </strong>{" "}
                        {projectId}
                    </p>
                )}

                {/* FILE SECTION */}
                <div>
                    <label htmlFor="file">
                        <strong>
                            Select Source File
                        </strong>
                    </label>

                    <br />
                    <br />

                    <input
                        id="file"
                        type="file"
                        onChange={
                            handleFileChange
                        }
                        disabled={
                            loadingUpload ||
                            loadingProjects ||
                            projects.length === 0
                        }
                    />
                </div>

                <br />

                {/* SELECTED FILE INFORMATION */}
                {file && (
                    <div>
                        <p>
                            <strong>
                                Selected file:
                            </strong>{" "}
                            {file.name}
                        </p>

                        <p>
                            <strong>
                                Size:
                            </strong>{" "}
                            {(
                                file.size / 1024
                            ).toFixed(2)}{" "}
                            KB
                        </p>
                    </div>
                )}

                <br />

                {/* ERROR */}
                {error && (
                    <div
                        style={{
                            padding: "12px",
                            marginBottom: "15px",
                            border: "1px solid #f5c2c7",
                            borderRadius: "6px",
                            backgroundColor:
                                "#f8d7da",
                            color: "#842029",
                        }}
                    >
                        <strong>Error:</strong>{" "}
                        {error}

                        <br />
                        <br />

                        <button
                            type="button"
                            onClick={() => {
                                setError("");
                                fetchProjects();
                            }}
                        >
                            Retry
                        </button>
                    </div>
                )}

                {/* SUCCESS */}
                {success && (
                    <div
                        style={{
                            padding: "12px",
                            marginBottom: "15px",
                            border: "1px solid #badbcc",
                            borderRadius: "6px",
                            backgroundColor:
                                "#d1e7dd",
                            color: "#0f5132",
                        }}
                    >
                        {success}
                    </div>
                )}

                {/* UPLOAD BUTTON */}
                <button
                    type="submit"
                    disabled={
                        loadingUpload ||
                        loadingProjects ||
                        projects.length === 0
                    }
                >
                    {loadingUpload
                        ? "Uploading and Scanning..."
                        : "Upload and Scan"}
                </button>
            </form>
        </div>
    );
}

export default Upload;