
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    getProjects,
    getProjectFiles,
} from "../services/projectService";

import { uploadFile } from "../services/uploadService";

import LoadingState from "../components/LoadingState";
import EmptyState from "../components/EmptyState";

const MAX_FILE_SIZE = 5 * 1024 * 1024;

const ALLOWED_EXTENSIONS = [
    ".py",
    ".js",
    ".java",
    ".html",
    ".zip",
];

function Upload() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);

    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingFiles, setLoadingFiles] = useState(false);
    const [loadingUpload, setLoadingUpload] = useState(false);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const fetchProjectFiles = async (selectedProjectId) => {
        try {
            setLoadingFiles(true);

            const response = await getProjectFiles(
                selectedProjectId
            );

            setUploadedFiles(
                Array.isArray(response.data)
                    ? response.data
                    : []
            );
        } catch (err) {
            console.error("Failed to load project files:", err);

            setUploadedFiles([]);

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    "Failed to load uploaded files."
            );
        } finally {
            setLoadingFiles(false);
        }
    };

    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const response = await getProjects();

            const projectList = Array.isArray(response.data)
                ? response.data
                : [];

            setProjects(projectList);

            const savedProjectId = localStorage.getItem(
                "selected_project_id"
            );

            const savedProjectExists = projectList.some(
                (project) =>
                    String(project.id) === String(savedProjectId)
            );

            if (savedProjectExists) {
                setProjectId(String(savedProjectId));
                await fetchProjectFiles(String(savedProjectId));
            } else {
                setProjectId("");
                setUploadedFiles([]);
                localStorage.removeItem("selected_project_id");
            }
        } catch (err) {
            console.error("Failed to load projects:", err);

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    "Failed to load projects."
            );
        } finally {
            setLoadingProjects(false);
        }
    };

    useEffect(() => {
        fetchProjects();
    }, []);

    const handleProjectChange = async (e) => {
        const selectedId = e.target.value;

        setProjectId(selectedId);
        setFile(null);
        setError("");
        setSuccess("");

        const fileInput = document.getElementById("file");

        if (fileInput) {
            fileInput.value = "";
        }

        if (selectedId) {
            localStorage.setItem(
                "selected_project_id",
                selectedId
            );

            await fetchProjectFiles(selectedId);
        } else {
            localStorage.removeItem("selected_project_id");
            setUploadedFiles([]);
        }
    };

    const handleFileChange = (e) => {
        const selectedFile = e.target.files?.[0];

        setFile(null);
        setError("");
        setSuccess("");

        if (!selectedFile) {
            return;
        }

        const fileName = selectedFile.name.toLowerCase();

        const isAllowed = ALLOWED_EXTENSIONS.some(
            (extension) => fileName.endsWith(extension)
        );

        if (!isAllowed) {
            setError(
                "Unsupported file type. Please select a .py, .js, .java, .html, or .zip file."
            );

            e.target.value = "";
            return;
        }

        if (selectedFile.size > MAX_FILE_SIZE) {
            setError(
                "File is too large. Maximum size is 5 MB."
            );

            e.target.value = "";
            return;
        }

        setFile(selectedFile);
    };

    const handleUpload = async (e) => {
        e.preventDefault();

        setError("");
        setSuccess("");

        if (!projectId) {
            setError("Please select a project.");
            return;
        }

        if (!file) {
            setError("Please select a valid source file.");
            return;
        }

        // Recheck the size before sending the request.
        if (file.size > MAX_FILE_SIZE) {
            setError("File is too large. Maximum size is 5 MB.");
            return;
        }

        setLoadingUpload(true);

        try {
            localStorage.setItem(
                "selected_project_id",
                String(projectId)
            );

            console.log("Sending project_id:", projectId);
            console.log("Sending file:", file.name);

            const response = await uploadFile(projectId, file);

            console.log("Upload response:", response.data);

            setSuccess(
                response.data?.message ||
                    "File uploaded successfully!"
            );

            setFile(null);

            const fileInput = document.getElementById("file");

            if (fileInput) {
                fileInput.value = "";
            }

            await fetchProjectFiles(projectId);
        } catch (err) {
            console.error("Upload failed:", err);

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    "Upload failed. Please try again."
            );
        } finally {
            setLoadingUpload(false);
        }
    };

    return (
        <main
            style={{
                width: "100%",
                maxWidth: "1000px",
                margin: "0 auto",
                padding: "24px",
                boxSizing: "border-box",
            }}
        >
            <header style={{ marginBottom: "24px" }}>
                <h1>Upload Source Code</h1>

                <p>
                    Select a project and upload source code for
                    security scanning.
                </p>
            </header>

            <section
                style={{
                    border: "1px solid #d1d5db",
                    borderRadius: "12px",
                    padding: "24px",
                    marginBottom: "32px",
                }}
            >
                <form onSubmit={handleUpload}>
                    <div style={{ marginBottom: "24px" }}>
                        <label htmlFor="project">
                            <strong>Select Project</strong>
                        </label>

                        <div style={{ marginTop: "10px" }}>
                            {loadingProjects ? (
                                <LoadingState message="Loading projects..." />
                            ) : projects.length === 0 ? (
                                <EmptyState
                                    title="No projects found"
                                    message="Create a project before uploading source code."
                                    buttonText="Go to Projects"
                                    onButtonClick={() =>
                                        navigate("/projects")
                                    }
                                />
                            ) : (
                                <select
                                    id="project"
                                    value={projectId}
                                    onChange={handleProjectChange}
                                    disabled={loadingUpload}
                                    style={{
                                        width: "100%",
                                        maxWidth: "500px",
                                        padding: "12px",
                                        borderRadius: "6px",
                                        border: "1px solid #9ca3af",
                                    }}
                                >
                                    <option value="">
                                        -- Select Project --
                                    </option>

                                    {projects.map((project) => (
                                        <option
                                            key={project.id}
                                            value={project.id}
                                        >
                                            {project.name}
                                        </option>
                                    ))}
                                </select>
                            )}
                        </div>
                    </div>

                    {projectId && (
                        <p>
                            <strong>Selected Project ID:</strong>{" "}
                            {projectId}
                        </p>
                    )}

                    <div style={{ marginBottom: "24px" }}>
                        <label htmlFor="file">
                            <strong>Select Source File</strong>
                        </label>

                        <p style={{ fontSize: "14px", color: "#6b7280" }}>
                            Allowed extensions: .py, .js, .java, .html,
                            .zip. Maximum size: 5 MB.
                        </p>

                        <input
                            id="file"
                            type="file"
                            accept=".py,.js,.java,.html,.zip"
                            onChange={handleFileChange}
                            disabled={
                                loadingUpload ||
                                loadingProjects ||
                                projects.length === 0 ||
                                !projectId
                            }
                        />
                    </div>

                    {file && (
                        <div
                            style={{
                                background: "#f3f4f6",
                                padding: "14px",
                                borderRadius: "8px",
                                marginBottom: "20px",
                                overflowWrap: "anywhere",
                            }}
                        >
                            <p>
                                <strong>Selected file:</strong>{" "}
                                {file.name}
                            </p>

                            <p>
                                <strong>Size:</strong>{" "}
                                {(file.size / 1024).toFixed(2)} KB
                            </p>
                        </div>
                    )}

                    {error && (
                        <div
                            role="alert"
                            style={{
                                padding: "12px",
                                marginBottom: "16px",
                                border: "1px solid #f5c2c7",
                                borderRadius: "6px",
                                backgroundColor: "#f8d7da",
                                color: "#842029",
                            }}
                        >
                            <strong>Error:</strong> {error}

                            <div style={{ marginTop: "12px" }}>
                                <button
                                    type="button"
                                    onClick={() => {
                                        setError("");
                                        fetchProjects();
                                    }}
                                    disabled={loadingUpload}
                                >
                                    Retry
                                </button>
                            </div>
                        </div>
                    )}

                    {success && (
                        <div
                            role="status"
                            style={{
                                padding: "12px",
                                marginBottom: "16px",
                                border: "1px solid #badbcc",
                                borderRadius: "6px",
                                backgroundColor: "#d1e7dd",
                                color: "#0f5132",
                            }}
                        >
                            {success}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={
                            loadingUpload ||
                            loadingProjects ||
                            projects.length === 0 ||
                            !projectId ||
                            !file
                        }
                        style={{
                            padding: "12px 22px",
                            borderRadius: "6px",
                            border: "none",
                            cursor: loadingUpload ? "wait" : "pointer",
                        }}
                    >
                        {loadingUpload ? "Uploading..." : "Upload File"}
                    </button>
                </form>
            </section>

            {projectId && (
                <section>
                    <h2>Uploaded Files</h2>

                    {loadingFiles ? (
                        <LoadingState message="Loading uploaded files..." />
                    ) : uploadedFiles.length === 0 ? (
                        <p>No files uploaded for this project yet.</p>
                    ) : (
                        <div>
                            {uploadedFiles.map((uploadedFile) => (
                                <article
                                    key={uploadedFile.id}
                                    style={{
                                        border: "1px solid #d1d5db",
                                        borderRadius: "8px",
                                        padding: "16px",
                                        marginBottom: "12px",
                                        overflowWrap: "anywhere",
                                    }}
                                >
                                    <p>
                                        <strong>File:</strong>{" "}
                                        {uploadedFile.filename}
                                    </p>

                                    <p>
                                        <strong>File ID:</strong>{" "}
                                        {uploadedFile.id}
                                    </p>

                                    <p>
                                        <strong>Uploaded:</strong>{" "}
                                        {uploadedFile.uploaded_at
                                            ? new Date(
                                                uploadedFile.uploaded_at
                                            ).toLocaleString()
                                            : "N/A"}
                                    </p>
                                </article>
                            ))}
                        </div>
                    )}
                </section>
            )}
        </main>
    );
}

export default Upload;
