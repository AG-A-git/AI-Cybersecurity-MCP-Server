import api from "./api";

export const getProjects = () => {
    return api.get("/projects");
};

export const createProject = (projectData) => {
    return api.post("/projects", projectData);
};

export const getProjectFiles = (projectId) => {
    return api.get(`/projects/${projectId}/files`);
};