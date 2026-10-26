import api from "./api";

export const getScans = async () => {
    const response = await api.get("/scans/");
    return response.data;
};

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

    // Backend success_response wraps the actual scan object in `data`.
    return response.data?.data ?? response.data;
};

export const retryScan = async (scanId) => {
    if (
        scanId === null ||
        scanId === undefined ||
        String(scanId).trim() === "" ||
        !Number.isInteger(Number(scanId)) ||
        Number(scanId) <= 0
    ) {
        throw new Error("A valid scan ID is required to retry a scan.");
    }

    const response = await api.post(`/scans/${Number(scanId)}/retry`);
    return response.data?.data ?? response.data;
};
