import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    getProjects,
    getProjectFiles,
} from "../services/projectService";

import { uploadFile } from "../services/uploadService";

import LoadingState from "../components/LoadingState";
import EmptyState from "../components/EmptyState";

function Upload() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectId, setProjectId] = useState("");
    const [file, setFile] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);

    const [loadingProjects, setLoadingProjects] = useState(true);
    const [loadingUpload, setLoadingUpload] = useState(false);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const response = await getProjects();

            console.log("Projects:", response.data);

            setProjects(response.data);

            const selectedProjectId =
                localStorage.getItem(
                    "selected_project_id"
                );

            if (selectedProjectId) {
                const selectedProjectExists =
                    response.data.some(
                        (project) =>
                            String(project.id) ===
                            String(selectedProjectId)
                    );

                if (selectedProjectExists) {
                    setProjectId(selectedProjectId);

                    await fetchProjectFiles(
                        selectedProjectId
                    );
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

    const fetchProjectFiles = async (
        selectedProjectId
    ) => {
        try {
            const response =
                await getProjectFiles(
                    selectedProjectId
                );

            console.log(
                "Uploaded files:",
                response.data
            );

            setUploadedFiles(
                response.data
            );
        } catch (error) {
            console.error(
                "Failed to load project files:",
                error
            );

            setUploadedFiles([]);
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

        if (selectedId) {
            localStorage.setItem(
                "selected_project_id",
                selectedId
            );

            await fetchProjectFiles(
                selectedId
            );
        } else {
            localStorage.removeItem(
                "selected_project_id"
            );

            setUploadedFiles([]);
        }
    };

    const handleFileChange = (e) => {
        const selectedFile =
            e.target.files[0];

        setFile(
            selectedFile || null
        );

        setError("");
        setSuccess("");
    };

    const handleUpload = async (e) => {
        e.preventDefault();

        setError("");
        setSuccess("");

        if (!projectId) {
            setError(
                "Please select a project."
            );
            return;
        }

        if (!file) {
            setError(
                "Please select a file."
            );
            return;
        }

        const maxSize =
            5 * 1024 * 1024;

        if (file.size > maxSize) {
            setError(
                "File is too large. Maximum size is 5 MB."
            );
            return;
        }

        setLoadingUpload(true);

        try {
            localStorage.setItem(
                "selected_project_id",
                String(projectId)
            );

            console.log(
                "Sending project_id:",
                projectId
            );

            console.log(
                "Sending file:",
                file.name
            );

            const response =
                await uploadFile(
                    projectId,
                    file
                );

            console.log(
                "Upload response:",
                response.data
            );

            setSuccess(
                "File uploaded successfully!"
            );

            await fetchProjectFiles(
                projectId
            );

            setFile(null);
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
        <div
            style={{
                padding: "30px",
            }}
        >
            <h1>
                Upload Source Code
            </h1>

            <p>
                Select a project and upload
                source code for security
                scanning.
            </p>

            <hr />

            <form
                onSubmit={handleUpload}
            >
                <div>
                    <label htmlFor="project">
                        <strong>
                            Select Project
                        </strong>
                    </label>

                    <br />
                    <br />

                    {loadingProjects ? (
                        <LoadingState
                            message="Loading projects..."
                        />
                    ) : projects.length === 0 ? (
                        <EmptyState
                            title="No projects found"
                            message="Please create a project before uploading source code."
                            buttonText="Go to Projects"
                            onButtonClick={() =>
                                navigate(
                                    "/projects"
                                )
                            }
                        />
                    ) : (
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
                                        key={
                                            project.id
                                        }
                                        value={
                                            project.id
                                        }
                                    >
                                        {
                                            project.name
                                        }
                                    </option>
                                )
                            )}
                        </select>
                    )}
                </div>

                <br />

                {projectId && (
                    <p>
                        <strong>
                            Selected Project ID:
                        </strong>{" "}
                        {projectId}
                    </p>
                )}

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
                            projects.length ===
                                0
                        }
                    />
                </div>

                <br />

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
                                file.size /
                                1024
                            ).toFixed(2)}{" "}
                            KB
                        </p>
                    </div>
                )}

                <br />

                {error && (
                    <div
                        style={{
                            padding: "12px",
                            marginBottom:
                                "15px",
                            border:
                                "1px solid #f5c2c7",
                            borderRadius:
                                "6px",
                            backgroundColor:
                                "#f8d7da",
                            color:
                                "#842029",
                        }}
                    >
                        <strong>
                            Error:
                        </strong>{" "}
                        {error}

                        <br />
                        <br />

                        <button
                            type="button"
                            onClick={() => {
                                setError(
                                    ""
                                );

                                fetchProjects();
                            }}
                        >
                            Retry
                        </button>
                    </div>
                )}

                {success && (
                    <div
                        style={{
                            padding: "12px",
                            marginBottom:
                                "15px",
                            border:
                                "1px solid #badbcc",
                            borderRadius:
                                "6px",
                            backgroundColor:
                                "#d1e7dd",
                            color:
                                "#0f5132",
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
                        projects.length ===
                            0
                    }
                >
                    {loadingUpload
                        ? "Uploading..."
                        : "Upload File"}
                </button>
            </form>

            {projectId && (
                <section
                    style={{
                        marginTop: "40px",
                    }}
                >
                    <hr />

                    <h2>
                        Uploaded Files
                    </h2>

                    {uploadedFiles.length ===
                    0 ? (
                        <p>
                            No files uploaded
                            for this project yet.
                        </p>
                    ) : (
                        <div>
                            {uploadedFiles.map(
                                (uploadedFile) => (
                                    <div
                                        key={
                                            uploadedFile.id
                                        }
                                        style={{
                                            border:
                                                "1px solid #ccc",
                                            borderRadius:
                                                "8px",
                                            padding:
                                                "15px",
                                            marginBottom:
                                                "10px",
                                        }}
                                    >
                                        <p>
                                            <strong>
                                                File:
                                            </strong>{" "}
                                            {
                                                uploadedFile.filename
                                            }
                                        </p>

                                        <p>
                                            <strong>
                                                File ID:
                                            </strong>{" "}
                                            {
                                                uploadedFile.id
                                            }
                                        </p>

                                        <p>
                                            <strong>
                                                Uploaded:
                                            </strong>{" "}
                                            {uploadedFile.uploaded_at
                                                ? new Date(
                                                    uploadedFile.uploaded_at
                                                ).toLocaleString()
                                                : "N/A"}
                                        </p>
                                    </div>
                                )
                            )}
                        </div>
                    )}
                </section>
            )}
        </div>
    );
}

export default Upload;
