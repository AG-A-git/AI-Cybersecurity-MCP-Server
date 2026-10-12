
import api from "./api";

// Get all scans
export const getScans = () => api.get("/scans/");

// Start a scan for a project
export const startScan = (projectId) =>
    api.post("/scans/", {
        project_id: Number(projectId),
    });

// Get details and vulnerabilities for one scan
export const getScanResults = (scanId) =>
    api.get(`/scans/${scanId}`);
