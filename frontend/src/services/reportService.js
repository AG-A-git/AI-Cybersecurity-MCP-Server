import api from "./api";

export const getReports = () => {
    return api.get("/reports");
};

/*
 * Report generation abstraction.
 *
 * The backend does not currently provide a
 * report-generation/download endpoint.
 *
 * This function is intentionally not connected
 * to a fake download.
 */
export const generateReport = (scanId, format) => {
    return Promise.reject(
        new Error(
            `Report generation is not available yet for scan ${scanId} in ${format} format.`
        )
    );
};