
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

// Fetch files for a project
// Temporary fallback until the backend route is implemented
export const getProjectFiles = async (projectId) => {
    console.warn(
        `Project file listing is unavailable for project ${projectId}: backend route is missing.`
    );

    return [];
};
