
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getProjects, getProjectFiles } from "../services/projectService";
import { uploadFile } from "../services/uploadService";
import { startScan } from "../services/scanService";

const Upload = () => {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [loadingProjects, setLoadingProjects] = useState(true);
    const [uploading, setUploading] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");

    // Fetch uploaded files for the selected project.
    const fetchProjectFiles = useCallback(async (id) => {
        if (!id) {
            setUploadedFiles([]);
            return;
        }

        try {
            const data = await getProjectFiles(id);

            setUploadedFiles(
                Array.isArray(data)
                    ? data
                    : Array.isArray(data?.files)
                        ? data.files
                        : []
            );
        } catch (err) {
            console.warn(
                "Could not load project files:",
                err.response?.status || err.message
            );
            setUploadedFiles([]);
        }
    }, []);

    // Fetch projects and restore the selected project.
    const fetchProjects = useCallback(async () => {
        setLoadingProjects(true);
        setError("");

        try {
            const data = await getProjects();

            const projectList = Array.isArray(data)
                ? data
                : Array.isArray(data?.projects)
                    ? data.projects
                    : [];

            setProjects(projectList);

            const savedId = localStorage.getItem("selected_project_id");

            const savedProject = projectList.find(
                (project) => String(project.id) === String(savedId)
            );

            const selectedProject = savedProject || projectList[0];
            const selectedId = selectedProject
                ? String(selectedProject.id)
                : "";

            setProjectId(selectedId);

            if (selectedId) {
                localStorage.setItem("selected_project_id", selectedId);
                await fetchProjectFiles(selectedId);
            } else {
                localStorage.removeItem("selected_project_id");
                setUploadedFiles([]);
            }
        } catch (err) {
            console.error("Failed to load projects:", err);

            setError(
                err.response?.data?.detail ||
                err.userMessage ||
                "Could not load projects. Check that the backend is running."
            );
        } finally {
            setLoadingProjects(false);
        }
    }, [fetchProjectFiles]);

    useEffect(() => {
        fetchProjects();
    }, [fetchProjects]);

    // Change the selected project.
    const handleProjectChange = async (event) => {
        const id = event.target.value;

        setProjectId(id);
        setFile(null);
        setMessage("");
        setError("");
        setUploadedFiles([]);

        const fileInput = document.getElementById("source-file");
        if (fileInput) fileInput.value = "";

        if (id) {
            localStorage.setItem("selected_project_id", id);
            await fetchProjectFiles(id);
        } else {
            localStorage.removeItem("selected_project_id");
        }
    };

    // Validate the selected file.
    const handleFileChange = (event) => {
        const selectedFile = event.target.files?.[0];

        setError("");
        setMessage("");

        if (!selectedFile) {
            setFile(null);
            return;
        }

        const allowedExtensions = [
            ".py",
            ".js",
            ".java",
            ".html",
            ".zip",
        ];

        const fileName = selectedFile.name.toLowerCase();

        const isAllowed = allowedExtensions.some((extension) =>
            fileName.endsWith(extension)
        );

        if (!isAllowed) {
            setFile(null);
            event.target.value = "";

            setError(
                "Choose a .py, .js, .java, .html, or .zip file."
            );
            return;
        }

        setFile(selectedFile);
    };

    // Upload the selected file.
    const handleUpload = async (event) => {
        event.preventDefault();

        setError("");
        setMessage("");

        if (!projectId) {
            setError("Please create or select a project first.");
            return;
        }

        if (!file) {
            setError("Please choose a file to upload.");
            return;
        }

        setUploading(true);

        try {
            const response = await uploadFile(projectId, file);
            const result = response?.data ?? response;

            setMessage(
                result?.message ||
                `File "${file.name}" uploaded successfully.`
            );

            setFile(null);

            const fileInput = document.getElementById("source-file");
            if (fileInput) fileInput.value = "";

            await fetchProjectFiles(projectId);
        } catch (err) {
            console.error("Upload failed:", err);

            setError(
                err.response?.data?.detail ||
                err.userMessage ||
                "Upload failed. Check the backend upload endpoint."
            );
        } finally {
            setUploading(false);
        }
    };

    // Start scanning and navigate to the Results page.
    const handleStartScan = async () => {
        if (!projectId) {
            setError("Please select a project first.");
            return;
        }

        setError("");
        setMessage("");
        setScanning(true);

        try {
            const response = await startScan(projectId);
            const result = response?.data ?? response;

            console.log("Scan response:", result);

            const scanId = result?.scan_id ?? result?.id;

            if (!scanId) {
                setError(
                    "The backend did not return a scan ID. Check the scan response."
                );
                return;
            }

            // Navigate to Results and pass the scan ID.
            navigate("/results", {
                state: {
                    scanId,
                    result,
                },
            });
        } catch (err) {
            console.error("Scan failed:", err);

            setError(
                err.response?.data?.detail ||
                err.userMessage ||
                "Could not start the scan. Check the backend scan endpoint."
            );
        } finally {
            setScanning(false);
        }
    };

    return (
        <main className="upload-page" style={styles.page}>
            <div style={styles.header}>
                <div>
                    <h1 style={styles.heading}>Upload Source Code</h1>
                    <p style={styles.subtitle}>
                        Select a project, upload source code, and start a scan.
                    </p>
                </div>

                <button
                    type="button"
                    onClick={fetchProjects}
                    disabled={loadingProjects}
                    style={styles.secondaryButton}
                >
                    {loadingProjects ? "Loading..." : "Reload Projects"}
                </button>
            </div>

            {error && (
                <div role="alert" style={styles.error}>
                    {String(error)}
                </div>
            )}

            {message && (
                <div role="status" style={styles.success}>
                    {String(message)}
                </div>
            )}

            {/* Project selection */}
            <section style={styles.card}>
                <label htmlFor="project-select" style={styles.label}>
                    Select Project
                </label>

                <select
                    id="project-select"
                    value={projectId}
                    onChange={handleProjectChange}
                    disabled={loadingProjects || projects.length === 0}
                    style={styles.input}
                >
                    <option value="">
                        {loadingProjects
                            ? "Loading projects..."
                            : projects.length === 0
                                ? "No projects found — create a project first"
                                : "Choose a project"}
                    </option>

                    {projects.map((project) => (
                        <option
                            key={project.id}
                            value={String(project.id)}
                        >
                            {project.project_name ||
                                project.name ||
                                `Project ${project.id}`}
                        </option>
                    ))}
                </select>

                {!loadingProjects && projects.length === 0 && (
                    <p style={styles.hint}>
                        Create a project first, then reload this page.
                    </p>
                )}
            </section>

            {/* File upload */}
            <section style={styles.card}>
                <h2 style={styles.subheading}>Choose a File</h2>

                <p style={styles.hint}>
                    Supported files: .py, .js, .java, .html, and .zip
                </p>

                <form onSubmit={handleUpload}>
                    <input
                        id="source-file"
                        type="file"
                        accept=".py,.js,.java,.html,.zip"
                        onChange={handleFileChange}
                        disabled={
                            loadingProjects ||
                            uploading ||
                            !projectId
                        }
                        style={styles.fileInput}
                    />

                    {file && (
                        <p style={styles.fileName}>
                            Selected: {file.name} (
                            {(file.size / 1024).toFixed(1)} KB)
                        </p>
                    )}

                    <button
                        type="submit"
                        disabled={!projectId || !file || uploading}
                        style={{
                            ...styles.primaryButton,
                            opacity:
                                !projectId || !file || uploading
                                    ? 0.6
                                    : 1,
                        }}
                    >
                        {uploading ? "Uploading..." : "Upload File"}
                    </button>
                </form>
            </section>

            {/* Uploaded files */}
            <section style={styles.card}>
                <h2 style={styles.subheading}>Uploaded Files</h2>

                {uploadedFiles.length > 0 ? (
                    <ul style={styles.fileList}>
                        {uploadedFiles.map((uploaded, index) => (
                            <li key={uploaded.id ?? index}>
                                {uploaded.filename ||
                                    uploaded.file_name ||
                                    uploaded.name ||
                                    `File ${uploaded.id ?? index + 1}`}
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p style={styles.hint}>
                        No files to display, or the backend file-list
                        endpoint is not available yet.
                    </p>
                )}
            </section>

            {/* Security scan */}
            <section style={styles.card}>
                <h2 style={styles.subheading}>Security Scan</h2>

                <p style={styles.hint}>
                    Upload your code first, then start a scan for the
                    selected project.
                </p>

                <button
                    type="button"
                    onClick={handleStartScan}
                    disabled={
                        !projectId ||
                        scanning ||
                        uploading ||
                        loadingProjects
                    }
                    style={{
                        ...styles.primaryButton,
                        opacity:
                            !projectId ||
                            scanning ||
                            uploading ||
                            loadingProjects
                                ? 0.6
                                : 1,
                    }}
                >
                    {scanning ? "Scanning..." : "Start Scan"}
                </button>
            </section>
        </main>
    );
};

const styles = {
    page: {
        width: "100%",
        maxWidth: "1000px",
        margin: "0 auto",
        padding: "24px",
        boxSizing: "border-box",
        color: "var(--text-primary, #1f2937)",
    },
    header: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "16px",
        marginBottom: "24px",
    },
    heading: {
        margin: "0 0 8px",
        fontSize: "28px",
    },
    subtitle: {
        margin: 0,
        color: "var(--text-secondary, #6b7280)",
    },
    card: {
        padding: "20px",
        marginBottom: "20px",
        border: "1px solid var(--border-color, #e5e7eb)",
        borderRadius: "12px",
        background: "var(--card-background, #ffffff)",
        boxSizing: "border-box",
    },
    subheading: {
        marginTop: 0,
        fontSize: "19px",
    },
    label: {
        display: "block",
        fontWeight: 600,
        marginBottom: "8px",
    },
    input: {
        width: "100%",
        maxWidth: "100%",
        padding: "12px",
        border: "1px solid #d1d5db",
        borderRadius: "8px",
        boxSizing: "border-box",
        background: "#ffffff",
        color: "#111827",
    },
    fileInput: {
        display: "block",
        width: "100%",
        maxWidth: "100%",
        margin: "12px 0 16px",
        padding: "8px 0",
    },
    fileName: {
        overflowWrap: "anywhere",
        fontSize: "14px",
    },
    hint: {
        color: "var(--text-secondary, #6b7280)",
        fontSize: "14px",
        lineHeight: 1.5,
    },
    primaryButton: {
        padding: "11px 18px",
        border: "none",
        borderRadius: "8px",
        background: "#2563eb",
        color: "#ffffff",
        cursor: "pointer",
        fontWeight: 600,
    },
    secondaryButton: {
        padding: "10px 14px",
        border: "1px solid #d1d5db",
        borderRadius: "8px",
        background: "#ffffff",
        color: "#111827",
        cursor: "pointer",
    },
    error: {
        padding: "12px 14px",
        marginBottom: "16px",
        borderRadius: "8px",
        background: "#fef2f2",
        color: "#b91c1c",
        overflowWrap: "anywhere",
    },
    success: {
        padding: "12px 14px",
        marginBottom: "16px",
        borderRadius: "8px",
        background: "#ecfdf5",
        color: "#065f46",
        overflowWrap: "anywhere",
    },
    fileList: {
        paddingLeft: "20px",
        overflowWrap: "anywhere",
    },
};

export default Upload;
