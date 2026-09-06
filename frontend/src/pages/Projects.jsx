import { useState } from "react";
import api from "../services/api";

function Projects() {
    const [projectName, setProjectName] = useState("");
    const [description, setDescription] = useState("");

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const handleCreate = async (e) => {
        e.preventDefault();

        setLoading(true);
        setError("");
        setSuccess("");

        try {
            const response = await api.post("/projects/", {
                project_name: projectName,
                description: description
            });

            console.log("Project created:", response.data);

            setSuccess("Project created successfully!");

            setProjectName("");
            setDescription("");

        } catch (error) {
            console.error("Project creation failed:", error);

            setError(
                error.response?.data?.detail ||
                "Failed to create project. Please check the backend."
            );
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <h1>Projects</h1>

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
                        rows="5"
                        required
                    />
                </div>

                <br />

                <button type="submit" disabled={loading}>
                    {loading ? "Creating..." : "Create"}
                </button>

            </form>

            {success && (
                <p>{success}</p>
            )}

            {error && (
                <p>{error}</p>
            )}
        </div>
    );
}

export default Projects;