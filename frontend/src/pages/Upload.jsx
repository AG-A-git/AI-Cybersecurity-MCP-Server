
import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { getProjects, getProjectFiles } from "../services/projectService";
import { uploadFile } from "../services/uploadService";
import { startScan } from "../services/scanService";
import "../styles/Upload.css";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".py", ".js", ".java", ".html", ".zip"];

const getProjectList = (data) => {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.projects)) return data.projects;
    if (Array.isArray(data?.data)) return data.data;
    return [];
};

const getErrorMessage = (err, fallback) =>
    err?.userMessage ||
    err?.response?.data?.detail ||
    fallback;

const Upload = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const fileInputRef = useRef(null);
    const requestIdRef = useRef(0);

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingFiles, setLoadingFiles] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");

    const fetchProjectFiles = useCallback(async (id) => {
        const requestId = ++requestIdRef.current;

        if (!id) {
            setUploadedFiles([]);
            setLoadingFiles(false);
            return;
        }

        setLoadingFiles(true);

        try {
            const data = await getProjectFiles(id);

            // Ignore results from an older project selection.
            if (requestId !== requestIdRef.current) return;

            setUploadedFiles(
                Array.isArray(data)
                    ? data
                    : Array.isArray(data?.files)
                        ? data.files
                        : []
            );
        } catch (err) {
            if (requestId !== requestIdRef.current) return;

            console.warn(
                "Could not load project files:",
                err.response?.status || err.message
            );
            setUploadedFiles([]);
        } finally {
            if (requestId === requestIdRef.current) {
                setLoadingFiles(false);
            }
        }
    }, []);

    const fetchProjects = useCallback(async () => {
        setLoadingProjects(true);
        setError("");
        setMessage("");

        try {
            const data = await getProjects();
            const projectList = getProjectList(data);

            setProjects(projectList);

            const preferredId =
                location.state?.projectId ??
                localStorage.getItem("selected_project_id");

            const preferredProject = projectList.find(
                (project) => String(project.id) === String(preferredId)
            );

            const selectedProject = preferredProject || projectList[0];
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
                getErrorMessage(
                    err,
                    "Could not load projects. Check that the backend is running."
                )
            );
        } finally {
            setLoadingProjects(false);
        }
    }, [fetchProjectFiles, location.state]);

    useEffect(() => {
        fetchProjects();
    }, [fetchProjects]);

    const handleProjectChange = async (event) => {
        const id = event.target.value;

        setProjectId(id);
        setFile(null);
        setMessage("");
        setError("");
        setUploadedFiles([]);

        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }

        if (id) {
            localStorage.setItem("selected_project_id", id);
            await fetchProjectFiles(id);
        } else {
            localStorage.removeItem("selected_project_id");
            await fetchProjectFiles("");
        }
    };

    const handleFileChange = (event) => {
        const selectedFile = event.target.files?.[0];

        setError("");
        setMessage("");

        if (!selectedFile) {
            setFile(null);
            return;
        }

        const fileName = selectedFile.name.toLowerCase();
        const isAllowed = ALLOWED_EXTENSIONS.some((extension) =>
            fileName.endsWith(extension)
        );

        if (!isAllowed) {
            setFile(null);
            event.target.value = "";
            setError("Choose a .py, .js, .java, .html, or .zip file.");
            return;
        }

        if (selectedFile.size > MAX_FILE_SIZE) {
            setFile(null);
            event.target.value = "";
            setError("File size must be 10 MB or less.");
            return;
        }

        setFile(selectedFile);
    };

    const handleUpload = async (event) => {
        event.preventDefault();

        if (uploading || scanning) return;

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

        if (file.size > MAX_FILE_SIZE) {
            setError("File size must be 10 MB or less.");
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

            if (fileInputRef.current) {
                fileInputRef.current.value = "";
            }

            await fetchProjectFiles(projectId);
        } catch (err) {
            console.error("Upload failed:", err);
            setError(
                getErrorMessage(
                    err,
                    "Upload failed. Check the backend upload endpoint."
                )
            );
        } finally {
            setUploading(false);
        }
    };

    const handleStartScan = async () => {
        if (uploading || scanning) return;

        setError("");
        setMessage("");

        if (!projectId) {
            setError("Please select a project first.");
            return;
        }

        setScanning(true);

        try {
            const response = await startScan(projectId);
            const result = response?.data ?? response;
            const scanId = result?.scan_id ?? result?.id;

            if (scanId == null) {
                setError(
                    "The backend did not return a scan ID. Check the scan response."
                );
                return;
            }

            navigate("/results", {
                state: {
                    scanId,
                    result,
                },
            });
        } catch (err) {
            console.error("Scan failed:", err);
            setError(
                getErrorMessage(
                    err,
                    "Could not start the scan. Check the backend scan endpoint."
                )
            );
        } finally {
            setScanning(false);
        }
    };

    const busy = loadingProjects || uploading || scanning;

    return (
        <main className="upload-page">
            <header className="upload-header">
                <div>
                    <p className="upload-eyebrow">SECURITY WORKSPACE</p>
                    <h1>Upload Source Code</h1>
                    <p className="upload-subtitle">
                        Choose a project, upload your source files, and launch
                        a security scan.
                    </p>
                </div>

                <button
                    type="button"
                    className="upload-button upload-button-secondary"
                    onClick={fetchProjects}
                    disabled={loadingProjects || uploading || scanning}
                >
                    {loadingProjects ? "Loading..." : "Reload Projects"}
                </button>
            </header>

            {error && (
                <div className="upload-alert upload-alert-error" role="alert">
                    <strong>Something went wrong</strong>
                    <span>{String(error)}</span>
                </div>
            )}

            {message && (
                <div
                    className="upload-alert upload-alert-success"
                    role="status"
                >
                    {String(message)}
                </div>
            )}

            <section className="upload-card">
                <div className="upload-section-heading">
                    <span className="upload-step">01</span>
                    <div>
                        <h2>Select Project</h2>
                        <p>Choose where this source code belongs.</p>
                    </div>
                </div>

                <label className="upload-label" htmlFor="project-select">
                    Project
                </label>

                <select
                    id="project-select"
                    className="upload-control"
                    value={projectId}
                    onChange={handleProjectChange}
                    disabled={loadingProjects || projects.length === 0 || busy}
                >
                    <option value="">
                        {loadingProjects
                            ? "Loading projects..."
                            : projects.length === 0
                                ? "No projects available"
                                : "Choose a project"}
                    </option>

                    {projects.map((project) => (
                        <option key={project.id} value={String(project.id)}>
                            {project.project_name ||
                                project.name ||
                                `Project ${project.id}`}
                        </option>
                    ))}
                </select>

                {!loadingProjects && projects.length === 0 && (
                    <p className="upload-hint">
                        Create a project first, then reload this page.
                        <button
                            type="button"
                            className="upload-text-button"
                            onClick={() => navigate("/projects")}
                        >
                            Go to Projects
                        </button>
                    </p>
                )}
            </section>

            <section className="upload-card">
                <div className="upload-section-heading">
                    <span className="upload-step">02</span>
                    <div>
                        <h2>Upload Source File</h2>
                        <p>
                            Select a supported file for your security scan.
                        </p>
                    </div>
                </div>

                <div className="upload-file-rules">
                    <span>Supported: .py, .js, .java, .html, .zip</span>
                    <span>Maximum file size: 10 MB</span>
                </div>

                <form onSubmit={handleUpload}>
                    <label className="upload-dropzone" htmlFor="source-file">
                        <span className="upload-file-icon" aria-hidden="true">
                            ↑
                        </span>
                        <strong>
                            {file ? file.name : "Choose a source file"}
                        </strong>
                        <span>
                            {file
                                ? `${(file.size / 1024).toFixed(1)} KB selected`
                                : "Browse files from your computer"}
                        </span>
                        <input
                            ref={fileInputRef}
                            id="source-file"
                            type="file"
                            accept=".py,.js,.java,.html,.zip"
                            onChange={handleFileChange}
                            disabled={busy || !projectId}
                        />
                    </label>

                    <div className="upload-actions">
                        <button
                            type="submit"
                            className="upload-button upload-button-primary"
                            disabled={!projectId || !file || busy}
                        >
                            {uploading ? "Uploading..." : "Upload File"}
                        </button>
                        {file && !uploading && (
                            <button
                                type="button"
                                className="upload-button upload-button-secondary"
                                onClick={() => {
                                    setFile(null);
                                    setError("");
                                    if (fileInputRef.current) {
                                        fileInputRef.current.value = "";
                                    }
                                }}
                            >
                                Remove File
                            </button>
                        )}
                    </div>
                </form>
            </section>

            <section className="upload-card">
                <div className="upload-section-heading">
                    <span className="upload-step">03</span>
                    <div>
                        <h2>Project Files</h2>
                        <p>Files currently reported for the selected project.</p>
                    </div>
                </div>

                {loadingFiles ? (
                    <p className="upload-hint">Loading project files...</p>
                ) : uploadedFiles.length > 0 ? (
                    <ul className="upload-file-list">
                        {uploadedFiles.map((uploaded, index) => (
                            <li key={uploaded.id ?? `${uploaded.filename}-${index}`}>
                                <span className="upload-listed-file-icon" aria-hidden="true">
                                    {"</>"}
                                </span>
                                <span className="upload-listed-file-name">
                                    {uploaded.filename ||
                                        uploaded.file_name ||
                                        uploaded.name ||
                                        `File ${uploaded.id ?? index + 1}`}
                                </span>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p className="upload-empty-state">
                        No files are listed for this project. Upload a file to
                        continue. If the file-list endpoint is unavailable,
                        this list may remain empty.
                    </p>
                )}
            </section>

            <section className="upload-scan-card">
                <div>
                    <p className="upload-eyebrow">READY WHEN YOU ARE</p>
                    <h2>Run Security Scan</h2>
                    <p>
                        Start a scan for the selected project after uploading
                        the source files you want analyzed.
                    </p>
                </div>

                <button
                    type="button"
                    className="upload-button upload-button-scan"
                    onClick={handleStartScan}
                    disabled={!projectId || busy}
                >
                    {scanning ? "Starting scan..." : "Start Scan"}
                    {!scanning && <span aria-hidden="true"> →</span>}
                </button>
            </section>
        </main>
    );
};

export default Upload;
