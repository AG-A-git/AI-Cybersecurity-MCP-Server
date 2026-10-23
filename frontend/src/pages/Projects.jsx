
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    getProjects,
    createProject,
} from "../services/projectService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import "../styles/Projects.css";

function getProjectList(data) {
    if (Array.isArray(data)) {
        return data;
    }

    if (Array.isArray(data?.projects)) {
        return data.projects;
    }

    if (Array.isArray(data?.data)) {
        return data.data;
    }

    return null;
}

function getErrorMessage(err, fallback) {
    const detail = err?.response?.data?.detail;

    if (err?.userMessage) {
        return err.userMessage;
    }

    if (typeof detail === "string") {
        return detail;
    }

    if (Array.isArray(detail)) {
        return detail
            .map((item) => item?.msg)
            .filter(Boolean)
            .join(", ") || fallback;
    }

    return err?.message || fallback;
}

function Projects() {
    const navigate = useNavigate();

    const [projectName, setProjectName] = useState("");
    const [description, setDescription] = useState("");
    const [projects, setProjects] = useState([]);

    const [loading, setLoading] = useState(false);
    const [loadingProjects, setLoadingProjects] = useState(true);
    const [error, setError] = useState("");
    const [projectsLoadError, setProjectsLoadError] = useState("");
    const [success, setSuccess] = useState("");

    const fetchProjects = useCallback(async () => {
        setLoadingProjects(true);
        setProjectsLoadError("");

        try {
            const data = await getProjects();
            const projectList = getProjectList(data);

            if (projectList === null) {
                throw new Error(
                    "Unexpected response while loading projects."
                );
            }

            setProjects(projectList);
        } catch (err) {
            console.error("Failed to fetch projects:", err);

            setProjectsLoadError(
                getErrorMessage(
                    err,
                    "Failed to load projects. Please try again."
                )
            );
        } finally {
            setLoadingProjects(false);
        }
    }, []);

    useEffect(() => {
        fetchProjects();
    }, [fetchProjects]);

    const handleCreate = async (event) => {
        event.preventDefault();

        if (loading) {
            return;
        }

        const trimmedName = projectName.trim();
        const trimmedDescription = description.trim();

        if (!trimmedName) {
            setError("Please enter a project name.");
            setSuccess("");
            return;
        }

        setLoading(true);
        setError("");
        setSuccess("");

        try {
            await createProject({
                project_name: trimmedName,
                description: trimmedDescription,
            });

            setProjectName("");
            setDescription("");
            setSuccess("Project created successfully.");

            await fetchProjects();
        } catch (err) {
            console.error("Project creation failed:", err);

            setError(
                getErrorMessage(
                    err,
                    "Failed to create project. Please try again."
                )
            );
        } finally {
            setLoading(false);
        }
    };

    const handleUpload = (project) => {
        const projectId = project.id;

        if (
            projectId === null ||
            projectId === undefined ||
            String(projectId).trim() === ""
        ) {
            setError(
                "This project does not have a valid ID. Unable to open upload."
            );
            setSuccess("");
            return;
        }

        navigate("/upload", {
            state: {
                projectId,
                projectName:
                    project.project_name ||
                    project.name ||
                    "Unnamed Project",
            },
        });
    };

    return (
        <main className="projects-page">
            <header className="projects-header">
                <div>
                    <p className="projects-eyebrow">
                        SECURITY WORKSPACE
                    </p>
                    <h1>Projects</h1>
                    <p className="projects-subtitle">
                        Organize your applications and prepare source code
                        for security scanning.
                    </p>
                </div>

                <div className="projects-header-summary">
                    <span className="projects-summary-label">
                        Total projects
                    </span>
                    <strong>
                        {loadingProjects ? "—" : projects.length}
                    </strong>
                </div>
            </header>

            <section
                className="projects-create-section projects-panel"
                aria-labelledby="create-project-heading"
            >
                <div className="projects-section-heading">
                    <div>
                        <h2 id="create-project-heading">
                            Create a project
                        </h2>
                        <p>
                            Add an application to your security workspace.
                        </p>
                    </div>
                </div>

                <form
                    className="projects-form"
                    onSubmit={handleCreate}
                >
                    <div className="projects-field">
                        <label htmlFor="projectName">
                            Project name
                        </label>

                        <input
                            id="projectName"
                            name="project_name"
                            type="text"
                            value={projectName}
                            onChange={(event) => {
                                setProjectName(event.target.value);
                                setError("");
                                setSuccess("");
                            }}
                            placeholder="e.g. My Web Application"
                            maxLength={150}
                            autoComplete="off"
                            required
                            disabled={loading}
                        />

                        <span className="projects-field-hint">
                            Use a clear name that identifies your application.
                        </span>
                    </div>

                    <div className="projects-field">
                        <label htmlFor="projectDescription">
                            Description
                            <span className="projects-optional">
                                Optional
                            </span>
                        </label>

                        <textarea
                            id="projectDescription"
                            name="description"
                            value={description}
                            onChange={(event) => {
                                setDescription(event.target.value);
                                setError("");
                                setSuccess("");
                            }}
                            placeholder="What does this application do?"
                            rows={3}
                            disabled={loading}
                        />
                    </div>

                    <div className="projects-form-footer">
                        <p>
                            Your project will appear in the list after
                            it is successfully created.
                        </p>

                        <button
                            type="submit"
                            className="projects-button"
                            disabled={loading || loadingProjects}
                        >
                            {loading ? (
                                <>
                                    <span
                                        className="projects-spinner"
                                        aria-hidden="true"
                                    />
                                    Creating...
                                </>
                            ) : (
                                <>
                                    <span aria-hidden="true">+</span>
                                    Create project
                                </>
                            )}
                        </button>
                    </div>
                </form>

                {error && (
                    <div className="projects-form-message">
                        <ErrorState message={error} />
                    </div>
                )}

                {success && (
                    <p
                        className="projects-success"
                        role="status"
                        aria-live="polite"
                    >
                        <span aria-hidden="true">✓</span>
                        {success}
                    </p>
                )}
            </section>

            <section
                className="projects-list-section"
                aria-labelledby="my-projects-heading"
            >
                <div className="projects-list-header">
                    <div>
                        <h2 id="my-projects-heading">
                            Your projects
                        </h2>
                        <p>
                            Select a project to upload source code and
                            begin a security scan.
                        </p>
                    </div>

                    <button
                        type="button"
                        className="projects-button projects-button-secondary"
                        onClick={fetchProjects}
                        disabled={loadingProjects}
                    >
                        {loadingProjects ? "Refreshing..." : "Refresh"}
                    </button>
                </div>

                {loadingProjects ? (
                    <LoadingState message="Loading projects..." />
                ) : projectsLoadError ? (
                    <ErrorState
                        message={projectsLoadError}
                        onRetry={fetchProjects}
                    />
                ) : projects.length === 0 ? (
                    <div className="projects-empty">
                        <EmptyState
                            title="No projects yet"
                            message="Create your first project above to start organizing security scans."
                        />
                    </div>
                ) : (
                    <div className="projects-grid">
                        {projects.map((project, index) => {
                            const projectId = project.id;
                            const projectTitle =
                                project.project_name ||
                                project.name ||
                                "Unnamed Project";

                            return (
                                <article
                                    className="project-card"
                                    key={
                                        projectId ??
                                        `${projectTitle}-${index}`
                                    }
                                >
                                    <div className="project-card-top">
                                        <div
                                            className="project-card-icon"
                                            aria-hidden="true"
                                        >
                                            {projectTitle
                                                .trim()
                                                .charAt(0)
                                                .toUpperCase() || "P"}
                                        </div>

                                        <span className="project-card-status">
                                            Project
                                        </span>
                                    </div>

                                    <h3>{projectTitle}</h3>

                                    <p className="project-card-description">
                                        {project.description ||
                                            "No description provided."}
                                    </p>

                                    <div className="project-card-meta">
                                        <span>
                                            Project ID
                                        </span>
                                        <strong>
                                            {projectId ?? "Unavailable"}
                                        </strong>
                                    </div>

                                    <div className="project-card-actions">
                                        <button
                                            type="button"
                                            className="projects-button"
                                            onClick={() =>
                                                handleUpload(project)
                                            }
                                            disabled={
                                                projectId === null ||
                                                projectId === undefined ||
                                                String(projectId).trim() === ""
                                            }
                                        >
                                            Upload source code
                                            <span aria-hidden="true">
                                                →
                                            </span>
                                        </button>
                                    </div>
                                </article>
                            );
                        })}
                    </div>
                )}
            </section>
        </main>
    );
}

export default Projects;
