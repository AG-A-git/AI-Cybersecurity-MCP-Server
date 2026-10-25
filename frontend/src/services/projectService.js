import api from "./api";

// Fetch all projects
export const getProjects = async () => {
    const response = await api.get("/projects/");
    return response.data;
};

// Create a project
export const createProject = async (projectData) => {
    const response = await api.post("/projects/", null, {
        params: {
            project_name: projectData.project_name,
            description: projectData.description || "",
        },
    });

    return response.data;
};

// Fetch files belonging to a project.

export const getProjectFiles = async (projectId) => {
    if (
        projectId === null ||
        projectId === undefined ||
        String(projectId).trim() === "" ||
        !Number.isInteger(Number(projectId)) ||
        Number(projectId) <= 0
    ) {
        throw new Error("A valid project ID is required to fetch uploaded files.");
    }

    const response = await api.get(
        `/projects/${Number(projectId)}/files`
    );

    return response.data;
};