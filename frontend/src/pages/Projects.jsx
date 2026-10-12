
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    getProjects,
    createProject,
} from "../services/projectService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function Projects() {
    const navigate = useNavigate();

    const [projectName, setProjectName] = useState("");
    const [description, setDescription] = useState("");
    const [projects, setProjects] = useState([]);

    const [loading, setLoading] = useState(false);
    const [loadingProjects, setLoadingProjects] = useState(true);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    // Fetch all projects
    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const data = await getProjects();

            console.log("Projects:", data);

            setProjects(Array.isArray(data) ? data : []);
        } catch (err) {
            console.error("Failed to fetch projects:", err);

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

    // Create a new project
    const handleCreate = async (e) => {
        e.preventDefault();

        const trimmedName = projectName.trim();

        if (!trimmedName) {
            setError("Please enter a project name.");
            return;
        }

        setLoading(true);
        setError("");
        setSuccess("");

        try {
            const project = await createProject({
                project_name: trimmedName,
                description: description.trim(),
            });

            console.log("Project created:", project);

            setSuccess("Project created successfully!");

            setProjectName("");
            setDescription("");

            await fetchProjects();
        } catch (err) {
            console.error("Project creation failed:", err);

            const detail = err.response?.data?.detail;

            setError(
                err.userMessage ||
                (typeof detail === "string"
                    ? detail
                    : Array.isArray(detail)
                    ? detail.map((item) => item.msg).join(", ")
                    : "Failed to create project.")
            );
        } finally {
            setLoading(false);
        }
    };

    // Open a project
    const handleOpenProject = (projectId) => {
        localStorage.setItem(
            "selected_project_id",
            String(projectId)
        );

        navigate("/upload");
    };

    // Navigate to upload for a selected project
    const handleUploadFile = (projectId) => {
        localStorage.setItem(
            "selected_project_id",
            String(projectId)
        );

        navigate("/upload");
    };

    return (
        <div style={{ padding: "30px" }}>
            <h1>Projects</h1>

            {/* Create Project */}
            <section>
                <h2>Create Project</h2>

                <form onSubmit={handleCreate}>
                    <div>
                        <label htmlFor="projectName">
                            Project Name
                        </label>

                        <br />

                        <input
                            id="projectName"
                            type="text"
                            value={projectName}
                            onChange={(e) =>
                                setProjectName(e.target.value)
                            }
                            placeholder="Enter project name"
                            required
                        />
                    </div>

                    <br />

                    <div>
                        <label htmlFor="description">
                            Description
                        </label>

                        <br />

                        <textarea
                            id="description"
                            value={description}
                            onChange={(e) =>
                                setDescription(e.target.value)
                            }
                            placeholder="Enter project description"
                            rows={5}
                        />
                    </div>

                    <br />

                    <button
                        type="submit"
                        disabled={loading}
                    >
                        {loading
                            ? "Creating..."
                            : "Create Project"}
                    </button>
                </form>

                {success && (
                    <p style={{ color: "green" }}>
                        {success}
                    </p>
                )}
            </section>

            {error && (
                <ErrorState
                    message={error}
                    onRetry={fetchProjects}
                />
            )}

            <hr />

            {/* Project List */}
            <section>
                <h2>My Projects</h2>

                {loadingProjects ? (
                    <LoadingState message="Loading projects..." />
                ) : projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create your first project to start uploading source code."
                    />
                ) : (
                    <div>
                        {projects.map((project) => (
                            <div
                                key={project.id}
                                style={{
                                    border: "1px solid #ccc",
                                    padding: "20px",
                                    marginBottom: "15px",
                                    borderRadius: "8px",
                                }}
                            >
                                <h3>
                                    {project.project_name ||
                                        "Unnamed Project"}
                                </h3>

                                <p>
                                    <strong>Description:</strong>{" "}
                                    {project.description ||
                                        "No description"}
                                </p>

                                <p>
                                    <strong>Project ID:</strong>{" "}
                                    {project.id}
                                </p>

                                <p>
                                    <strong>Owner ID:</strong>{" "}
                                    {project.owner_id ?? "N/A"}
                                </p>

                                <p>
                                    <strong>Created:</strong>{" "}
                                    {project.created_at
                                        ? new Date(
                                              project.created_at
                                          ).toLocaleString()
                                        : "N/A"}
                                </p>

                                <div
                                    style={{
                                        display: "flex",
                                        flexWrap: "wrap",
                                        gap: "10px",
                                        marginTop: "15px",
                                    }}
                                >
                                    <button
                                        type="button"
                                        onClick={() =>
                                            handleOpenProject(
                                                project.id
                                            )
                                        }
                                    >
                                        Open Project
                                    </button>

                                    <button
                                        type="button"
                                        onClick={() =>
                                            handleUploadFile(
                                                project.id
                                            )
                                        }
                                    >
                                        Upload File
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </section>
        </div>
    );
}

export default Projects;
