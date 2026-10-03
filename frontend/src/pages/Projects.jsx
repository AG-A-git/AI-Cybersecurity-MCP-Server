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
    const [loadingProjects, setLoadingProjects] =
        useState(true);

    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const fetchProjects = async () => {
        try {
            setLoadingProjects(true);
            setError("");

            const response = await getProjects();

            console.log(
                "Projects:",
                response.data
            );

            setProjects(
                Array.isArray(response.data)
                    ? response.data
                    : []
            );
        } catch (error) {
            console.error(
                "Failed to fetch projects:",
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

    const handleCreate = async (e) => {
        e.preventDefault();

        setLoading(true);
        setError("");
        setSuccess("");

        try {
            const response =
                await createProject({
                    name: projectName,
                    description: description,
                });

            console.log(
                "Project created:",
                response.data
            );

            setSuccess(
                "Project created successfully!"
            );

            setProjectName("");
            setDescription("");

            await fetchProjects();
        } catch (error) {
            console.error(
                "Project creation failed:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Failed to create project."
            );
        } finally {
            setLoading(false);
        }
    };

    const handleOpenProject = (
        projectId
    ) => {
        localStorage.setItem(
            "selected_project_id",
            String(projectId)
        );

        navigate("/upload");
    };

    const handleUploadFile = (projectId) => {
        localStorage.setItem(
            "selected_project_id",
            String(projectId)
        );

        navigate("/upload");
    };

    return (
        <div
            style={{
                padding: "30px",
            }}
        >
            <h1>Projects</h1>

            <section>
                <h2>Create Project</h2>

                <form
                    onSubmit={handleCreate}
                >
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
                                setProjectName(
                                    e.target.value
                                )
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
                                setDescription(
                                    e.target.value
                                )
                            }
                            placeholder="Enter project description"
                            rows="5"
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
                    <p
                        style={{
                            color: "green",
                        }}
                    >
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

            <section>
                <h2>My Projects</h2>

                {loadingProjects ? (
                    <LoadingState
                        message="Loading projects..."
                    />
                ) : projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create your first project to start uploading source code."
                    />
                ) : (
                    <div>
                        {projects.map(
                            (project) => (
                                <div
                                    key={
                                        project.id
                                    }
                                    style={{
                                        border:
                                            "1px solid #ccc",
                                        padding:
                                            "20px",
                                        marginBottom:
                                            "15px",
                                        borderRadius:
                                            "8px",
                                    }}
                                >
                                    <h3>
                                        {
                                            project.name
                                        }
                                    </h3>

                                    <p>
                                        <strong>
                                            Description:
                                        </strong>{" "}
                                        {project.description ||
                                            "No description"}
                                    </p>

                                    <p>
                                        <strong>
                                            Project ID:
                                        </strong>{" "}
                                        {
                                            project.id
                                        }
                                    </p>

                                    <p>
                                        <strong>
                                            Owner ID:
                                        </strong>{" "}
                                        {
                                            project.owner_id
                                        }
                                    </p>

                                    <p>
                                        <strong>
                                            Created:
                                        </strong>{" "}
                                        {project.created_at
                                            ? new Date(
                                                project.created_at
                                            ).toLocaleString()
                                            : "N/A"}
                                    </p>

                                    <div
                                        style={{
                                            display:
                                                "flex",
                                            gap:
                                                "10px",
                                            marginTop:
                                                "15px",
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
                            )
                        )}
                    </div>
                )}
            </section>
        </div>
    );
}

export default Projects;
