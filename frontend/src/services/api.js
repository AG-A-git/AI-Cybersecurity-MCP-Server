import axios from "axios";
import { normalizeApiError } from "../utils/apiError";

const api = axios.create({
    baseURL: "http://127.0.0.1:8002",
});

// Add JWT token automatically to every request
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("access_token");

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        // Let the browser set the multipart/form-data boundary
        if (config.data instanceof FormData) {
            delete config.headers["Content-Type"];
        }

        return config;
    },
    (error) => Promise.reject(error)
);

// Handle API errors without automatically redirecting to login
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            console.error(
                "Authentication failed:",
                error.config?.method,
                error.config?.url,
                error.response?.data
            );
        }

        error.userMessage = normalizeApiError(error);
        return Promise.reject(error);
    }
);

export default api;
