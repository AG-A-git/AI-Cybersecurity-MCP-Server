
import api from "./api";

// Fetch all scans
export const getScans = async () => {
    const response = await api.get("/scans/");
    return response.data;
};

// Start a scan for a project
export const startScan = async (projectId) => {
    const response = await api.post("/scans/", {
        project_id: Number(projectId),
    });
    return response.data;
};

// Get details for one scan
export const getScanResults = async (scanId) => {
    const response = await api.get(`/scans/${scanId}`);
    return response.data;
};
