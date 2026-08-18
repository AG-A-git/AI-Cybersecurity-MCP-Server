import { useState } from "react";

function Projects() {
    const [projectName, setProjectName] = useState("");
    const [description, setDescription] = useState("");

    const handleCreate = (e) => {
        e.preventDefault();

        console.log("Project Name:", projectName);
        console.log("Description:", description);

        alert("Project form submitted!");

        setProjectName("");
        setDescription("");
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

                <button type="submit">
                    Create
                </button>
            </form>
        </div>
    );
}

export default Projects;