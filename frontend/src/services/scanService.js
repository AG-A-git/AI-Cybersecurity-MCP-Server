import api from "./api";

export const getScans = () => {
    return api.get("/scans");
};

export const uploadAndScan = (projectId, file) => {
    const formData = new FormData();

    formData.append("project_id", projectId);
    formData.append("file", file);

    return api.post("/upload", formData);
};