import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function Projects() {
    const navigate = useNavigate();

    const [projectName, setProjectName] = useState("");
    const [description, setDescription] = useState("");

    const [projects, setProjects] = useState([]);

    const [loading, setLoading] = useState(false);
    const [loadingProjects, setLoadingProjects] = useState(true);

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
        } catch (error) {
            console.error("Failed to fetch projects:", error);

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
    // CREATE PROJECT
    // =====================================================

    const handleCreate = async (e) => {
        e.preventDefault();

        setLoading(true);
        setError("");
        setSuccess("");

        try {
            const response = await api.post("/projects/", {
                name: projectName,
                description: description,
            });

            console.log("Project created:", response.data);

            setSuccess("Project created successfully!");

            // Clear form
            setProjectName("");
            setDescription("");

            // Reload project list
            await fetchProjects();
        } catch (error) {
            console.error("Project creation failed:", error);

            setError(
                error.userMessage ||
                error.response?.data?.detail ||
                "Failed to create project."
            );
        } finally {
            setLoading(false);
        }
    };

    // =====================================================
    // OPEN PROJECT
    // =====================================================

    const handleOpenProject = (projectId) => {
        navigate(`/projects/${projectId}`);
    };

    // =====================================================
    // START SCAN
    // =====================================================

    const handleScan = (projectId) => {
        navigate(`/projects/${projectId}/scan`);
    };

    return (
        <div style={{ padding: "30px" }}>

            {/* =================================================
                PAGE TITLE
            ================================================= */}

            <h1>Projects</h1>

            {/* =================================================
                CREATE PROJECT
            ================================================= */}

            <h2>Create Project</h2>

            <form onSubmit={handleCreate}>

                {/* PROJECT NAME */}

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

                {/* DESCRIPTION */}

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
                        rows="5"
                    />
                </div>

                <br />

                {/* CREATE BUTTON */}

                <button
                    type="submit"
                    disabled={loading}
                >
                    {loading ? "Creating..." : "Create Project"}
                </button>

            </form>

            {/* =================================================
                SUCCESS MESSAGE
            ================================================= */}

            {success && (
                <p style={{ color: "green" }}>
                    {success}
                </p>
            )}

            {/* =================================================
                ERROR MESSAGE
            ================================================= */}

            {error && (
                <p style={{ color: "red" }}>
                    {error}
                </p>
            )}

            <hr />

            {/* =================================================
                PROJECT LIST
            ================================================= */}

            <h2>My Projects</h2>

            {loadingProjects ? (
                <p>Loading projects...</p>
            ) : projects.length === 0 ? (
                <div>
                    <p>No projects found.</p>

                    <p>
                        Create your first project to start scanning.
                    </p>
                </div>
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

                            {/* PROJECT NAME */}

                            <h3>
                                {project.name}
                            </h3>

                            {/* DESCRIPTION */}

                            <p>
                                <strong>Description:</strong>{" "}
                                {project.description ||
                                    "No description"}
                            </p>

                            {/* PROJECT ID */}

                            <p>
                                <strong>Project ID:</strong>{" "}
                                {project.id}
                            </p>

                            {/* OWNER */}

                            <p>
                                <strong>Owner ID:</strong>{" "}
                                {project.owner_id}
                            </p>

                            {/* CREATED DATE */}

                            <p>
                                <strong>Created:</strong>{" "}
                                {project.created_at
                                    ? new Date(
                                        project.created_at
                                    ).toLocaleString()
                                    : "N/A"}
                            </p>

                            {/* ACTION BUTTONS */}

                            <div
                                style={{
                                    display: "flex",
                                    gap: "10px",
                                    marginTop: "15px",
                                }}
                            >

                                <button
                                    onClick={() =>
                                        handleOpenProject(
                                            project.id
                                        )
                                    }
                                >
                                    Open Project
                                </button>

                                <button
                                    onClick={() =>
                                        handleScan(project.id)
                                    }
                                >
                                    Scan
                                </button>

                            </div>

                        </div>
                    ))}

                </div>
            )}

        </div>
    );
}

export default Projects;