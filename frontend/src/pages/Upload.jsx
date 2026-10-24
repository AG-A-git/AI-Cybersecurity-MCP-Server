
import { useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { getProjects, getProjectFiles } from "../services/projectService";
import { uploadFile } from "../services/uploadService";
import { startScan } from "../services/scanService";
import "../styles/Upload.css";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".py", ".js", ".java", ".html", ".zip"];

const getErrorMessage = (error, fallback) => {
    if (error?.userMessage) return error.userMessage;

    const detail = error?.response?.data?.detail;

    if (typeof detail === "string" && detail.trim()) {
        return detail;
    }

    return fallback;
};

function Upload() {
    const navigate = useNavigate();
    const location = useLocation();

    const fileInputRef = useRef(null);
    const requestIdRef = useRef(0);

    // Synchronously prevents duplicate scan submissions.
    const scanInFlightRef = useRef(false);
    const uploadInFlightRef = useRef(false);

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);
    const [projectFiles, setProjectFiles] = useState([]);

    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingFiles, setLoadingFiles] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [scanning, setScanning] = useState(false);

    const [error, setError] = useState("");
    const [message, setMessage] = useState("");
    const [filesError, setFilesError] = useState("");

    const fetchProjectFiles = useCallback(async (selectedProjectId) => {
        if (!selectedProjectId) {
            setProjectFiles([]);
            setFilesError("");
            return;
        }

        const requestId = ++requestIdRef.current;

        setLoadingFiles(true);
        setFilesError("");

        try {
            const response = await getProjectFiles(selectedProjectId);

            if (requestId !== requestIdRef.current) return;

            const data = response?.data ?? response;
            const files = Array.isArray(data)
                ? data
                : data?.files ?? data?.uploaded_files ?? [];

            setProjectFiles(Array.isArray(files) ? files : []);
        } catch (err) {
            if (requestId !== requestIdRef.current) return;

            console.error("Failed to load project files:", err);
            setProjectFiles([]);
            setFilesError(
                getErrorMessage(
                    err,
                    "Could not load this project's uploaded files."
                )
            );
        } finally {
            if (requestId === requestIdRef.current) {
                setLoadingFiles(false);
            }
        }
    }, []);

    const fetchProjects = useCallback(async () => {
        setLoadingProjects(true);
        setError("");

        try {
            const response = await getProjects();
            const data = response?.data ?? response;
            const list = Array.isArray(data)
                ? data
                : data?.projects ?? [];

            setProjects(Array.isArray(list) ? list : []);

            const savedProjectId =
                localStorage.getItem("selected_project_id");

            const requestedProjectId =
                location.state?.projectId ??
                savedProjectId ??
                "";

            const matchingProject = list.find(
                (project) =>
                    String(project.id) === String(requestedProjectId)
            );

            if (matchingProject) {
                setProjectId(String(matchingProject.id));
            } else if (list.length === 1) {
                setProjectId(String(list[0].id));
            } else {
                setProjectId("");
            }
        } catch (err) {
            console.error("Failed to load projects:", err);
            setProjects([]);
            setError(
                getErrorMessage(
                    err,
                    "Could not load projects. Please try again."
                )
            );
        } finally {
            setLoadingProjects(false);
        }
    }, [location.state]);

    useEffect(() => {
        void fetchProjects();
    }, [fetchProjects]);

    useEffect(() => {
        if (projectId) {
            localStorage.setItem("selected_project_id", projectId);
            void fetchProjectFiles(projectId);
        } else {
            ++requestIdRef.current;
            setProjectFiles([]);
            setFilesError("");
            setLoadingFiles(false);
        }
    }, [projectId, fetchProjectFiles]);

    const handleProjectChange = (event) => {
        const nextProjectId = event.target.value;

        setProjectId(nextProjectId);
        setFile(null);
        setError("");
        setMessage("");

        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }
    };

    const handleFileChange = (event) => {
        setError("");
        setMessage("");

        const selectedFile = event.target.files?.[0];

        if (!selectedFile) {
            setFile(null);
            return;
        }

        const lowerName = selectedFile.name.toLowerCase();
        const extension = ALLOWED_EXTENSIONS.find((ext) =>
            lowerName.endsWith(ext)
        );

        if (!extension) {
            setFile(null);
            event.target.value = "";
            setError(
                "Unsupported file type. Choose a .py, .js, .java, .html, or .zip file."
            );
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

        if (
            uploadInFlightRef.current ||
            scanInFlightRef.current ||
            uploading ||
            scanning
        ) {
            return;
        }

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

        uploadInFlightRef.current = true;
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
            uploadInFlightRef.current = false;
            setUploading(false);
        }
    };

    const handleStartScan = async () => {
        // Ref guard works immediately, before React rerenders.
        if (
            uploadInFlightRef.current ||
            scanInFlightRef.current ||
            uploading ||
            scanning
        ) {
            return;
        }

        setError("");
        setMessage("");

        if (!projectId) {
            setError("Please select a project first.");
            return;
        }

        scanInFlightRef.current = true;
        setScanning(true);

        try {
            const response = await startScan(projectId);
            const envelope = response?.data ?? response;
            const result = envelope?.data ?? envelope;

            const scanId = result?.scan_id ?? result?.id;

            if (
                scanId == null ||
                String(scanId).trim() === ""
            ) {
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
            scanInFlightRef.current = false;
            setScanning(false);
        }
    };

    const busy = loadingProjects || uploading || scanning;

    return (
        <main className="upload-page">
            <header className="upload-header">
                <div>
                    <p className="upload-eyebrow">SECURITY WORKSPACE</p>
                    <h1>Upload &amp; Scan</h1>
                    <p>
                        Select a project, upload source code, and start a
                        vulnerability scan.
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
                <div className="upload-error" role="alert">
                    {error}
                </div>
            )}

            {message && (
                <div className="upload-success" role="status">
                    {message}
                </div>
            )}

            <section className="upload-section">
                <h2>Select a project</h2>

                <label htmlFor="project-select">Project</label>

                <select
                    id="project-select"
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
                            {project.name ?? project.title ?? `Project ${project.id}`}
                        </option>
                    ))}
                </select>

                {!loadingProjects && projects.length === 0 && (
                    <p role="status">
                        Create a project before uploading files.
                    </p>
                )}
            </section>

            <section className="upload-section">
                <h2>Upload source code</h2>

                <form onSubmit={handleUpload}>
                    <label htmlFor="source-file">Choose a file</label>

                    <input
                        ref={fileInputRef}
                        id="source-file"
                        name="file"
                        type="file"
                        accept=".py,.js,.java,.html,.zip"
                        onChange={handleFileChange}
                        disabled={busy || !projectId}
                    />

                    <p>
                        Supported formats: .py, .js, .java, .html, .zip.
                        Maximum size: 10 MB.
                    </p>

                    {file && (
                        <p role="status">
                            Selected: {file.name}
                        </p>
                    )}

                    <button
                        type="submit"
                        className="upload-button upload-button-primary"
                        disabled={!projectId || !file || busy}
                    >
                        {uploading ? "Uploading..." : "Upload File"}
                    </button>
                </form>
            </section>

            <section className="upload-section">
                <div className="upload-section-heading">
                    <h2>Project files</h2>

                    <button
                        type="button"
                        className="upload-button upload-button-secondary"
                        onClick={() => fetchProjectFiles(projectId)}
                        disabled={
                            !projectId ||
                            loadingFiles ||
                            uploading ||
                            scanning
                        }
                    >
                        {loadingFiles ? "Loading files..." : "Refresh Files"}
                    </button>
                </div>

                {filesError && (
                    <div className="upload-error" role="alert">
                        <p>{filesError}</p>

                        <button
                            type="button"
                            className="upload-button upload-button-secondary"
                            onClick={() => fetchProjectFiles(projectId)}
                            disabled={!projectId || loadingFiles || busy}
                        >
                            Retry
                        </button>
                    </div>
                )}

                {!filesError && loadingFiles && (
                    <p role="status">Loading project files...</p>
                )}

                {!filesError && !loadingFiles && projectId &&
                    projectFiles.length === 0 && (
                        <p role="status">
                            No uploaded files found for this project yet.
                        </p>
                    )}

                {!filesError && projectFiles.length > 0 && (
                    <ul>
                        {projectFiles.map((item, index) => (
                            <li
                                key={
                                    item.id ??
                                    `${item.filename ?? item.file_name ?? "file"}-${index}`
                                }
                            >
                                {item.filename ??
                                    item.file_name ??
                                    item.name ??
                                    "Uploaded file"}
                            </li>
                        ))}
                    </ul>
                )}
            </section>

            <section className="upload-section">
                <h2>Start security scan</h2>

                <p>
                    The scanner will analyze uploaded files associated with
                    the selected project.
                </p>

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
}

export default Upload;
