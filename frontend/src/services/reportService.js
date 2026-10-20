import api from "./api";

const VALID_FORMATS = new Set(["json", "html", "pdf"]);

export const downloadScanReport = async (scanId, format = "pdf") => {
    if (
        scanId === null ||
        scanId === undefined ||
        String(scanId).trim() === "" ||
        !Number.isInteger(Number(scanId)) ||
        Number(scanId) <= 0
    ) {
        throw new Error("A valid scan ID is required to download a report.");
    }

    const normalizedFormat = String(format).trim().toLowerCase();

    if (!VALID_FORMATS.has(normalizedFormat)) {
        throw new Error("Report format must be JSON, HTML, or PDF.");
    }

    return api.get(`/scans/${Number(scanId)}/report`, {
        params: { format: normalizedFormat },
        responseType: "blob",
    });
};