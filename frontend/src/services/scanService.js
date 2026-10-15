
import api from "./api";

// Fetch all scans
export const getScans = async () => {
    const response = await api.get("/scans/");
    return response.data;
};

// Start a scan for a project
export const startScan = async (projectId) => {
    if (
        projectId === null ||
        projectId === undefined ||
        String(projectId).trim() === "" ||
        !Number.isInteger(Number(projectId)) ||
        Number(projectId) <= 0
    ) {
        throw new Error("A valid project ID is required to start a scan.");
    }

    const response = await api.post("/scans/", {
        project_id: Number(projectId),
    });

    return response.data;
};

// Get details for one scan
export const getScanResults = async (scanId) => {
    if (
        scanId === null ||
        scanId === undefined ||
        String(scanId).trim() === "" ||
        !Number.isInteger(Number(scanId)) ||
        Number(scanId) <= 0
    ) {
        throw new Error("A valid scan ID is required to fetch scan results.");
    }

    const response = await api.get(`/scans/${Number(scanId)}`);
    return response.data;
};
