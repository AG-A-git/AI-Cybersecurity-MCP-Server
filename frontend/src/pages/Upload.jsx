import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Upload() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);

    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingUpload, setLoadingUpload] = useState(false);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    // =====================================================
    // GET PROJECTS
    // =====================================================

    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const response = await api.get("/projects/");

            console.log("Projects:", response.data);

            setProjects(response.data);

            // -------------------------------------------------
            // GET SELECTED PROJECT FROM LOCAL STORAGE
            // -------------------------------------------------

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

    // =====================================================
    // LOAD PROJECTS WHEN PAGE OPENS
    // =====================================================

    useEffect(() => {
        fetchProjects();
    }, []);

    // =====================================================
    // PROJECT CHANGE
    // =====================================================

    const handleProjectChange = (e) => {
        const selectedId = e.target.value;

        setProjectId(selectedId);

        // Keep selected project available to other pages
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

    // =====================================================
    // FILE CHANGE
    // =====================================================

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];

        setFile(selectedFile || null);

        setError("");
        setSuccess("");
    };

    // =====================================================
    // UPLOAD + SCAN
    // =====================================================

    const handleUpload = async (e) => {
        e.preventDefault();

        setError("");
        setSuccess("");

        // -------------------------------------------------
        // PROJECT CHECK
        // -------------------------------------------------

        if (!projectId) {
            setError("Please select a project.");
            return;
        }

        // -------------------------------------------------
        // FILE CHECK
        // -------------------------------------------------

        if (!file) {
            setError("Please select a file.");
            return;
        }

        // -------------------------------------------------
        // FILE SIZE CHECK
        // -------------------------------------------------

        const maxSize = 5 * 1024 * 1024;

        if (file.size > maxSize) {
            setError(
                "File is too large. Maximum size is 5 MB."
            );
            return;
        }

        setLoadingUpload(true);

        try {
            // -------------------------------------------------
            // STORE SELECTED PROJECT
            // -------------------------------------------------

            localStorage.setItem(
                "selected_project_id",
                String(projectId)
            );

            // -------------------------------------------------
            // CREATE FORM DATA
            // -------------------------------------------------

            const formData = new FormData();

            formData.append(
                "project_id",
                String(projectId)
            );

            formData.append(
                "file",
                file
            );

            // -------------------------------------------------
            // DEBUG
            // -------------------------------------------------

            console.log(
                "Sending project_id:",
                projectId
            );

            console.log(
                "Sending file:",
                file.name
            );

            // -------------------------------------------------
            // API REQUEST
            // -------------------------------------------------

            const response = await api.post(
                "/upload",
                formData
            );

            console.log(
                "Upload response:",
                response.data
            );

            // -------------------------------------------------
            // SUCCESS
            // -------------------------------------------------

            setSuccess(
                "Security scan completed!"
            );

            // -------------------------------------------------
            // GO TO SCAN RESULTS
            // -------------------------------------------------

            navigate(
                "/scan-results",
                {
                    state: {
                        result: response.data,
                        projectId: projectId
                    }
                }
            );
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

    // =====================================================
    // UI
    // =====================================================

    return (
        <div
            style={{
                padding: "30px"
            }}
        >
            {/* =================================================
                TITLE
            ================================================= */}

            <h1>
                Upload Source Code
            </h1>

            <p>
                Select a project and upload
                source code for security scanning.
            </p>

            <hr />

            {/* =================================================
                FORM
            ================================================= */}

            <form onSubmit={handleUpload}>

                {/* =================================================
                    PROJECT
                ================================================= */}

                <div>
                    <label htmlFor="project">
                        <strong>
                            Select Project
                        </strong>
                    </label>

                    <br />
                    <br />

                    {loadingProjects ? (
                        <p>
                            Loading projects...
                        </p>
                    ) : projects.length === 0 ? (
                        <div>
                            <p>
                                No projects found.
                                Please create a project first.
                            </p>

                            <button
                                type="button"
                                onClick={() =>
                                    navigate("/projects")
                                }
                            >
                                Go to Projects
                            </button>
                        </div>
                    ) : (
                        <select
                            id="project"
                            value={projectId}
                            onChange={handleProjectChange}
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

                {/* =================================================
                    SELECTED PROJECT
                ================================================= */}

                {projectId && (
                    <p>
                        <strong>
                            Selected Project ID:
                        </strong>{" "}
                        {projectId}
                    </p>
                )}

                {/* =================================================
                    FILE
                ================================================= */}

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
                        onChange={handleFileChange}
                    />
                </div>

                <br />

                {/* =================================================
                    SELECTED FILE
                ================================================= */}

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

                {/* =================================================
                    ERROR
                ================================================= */}

                {error && (
                    <p
                        style={{
                            color: "red"
                        }}
                    >
                        {error}
                    </p>
                )}

                {/* =================================================
                    SUCCESS
                ================================================= */}

                {success && (
                    <p
                        style={{
                            color: "green"
                        }}
                    >
                        {success}
                    </p>
                )}

                {/* =================================================
                    BUTTON
                ================================================= */}

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