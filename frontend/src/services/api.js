
import axios from "axios";
import { normalizeApiError } from "../utils/apiError";

const api = axios.create({
    baseURL: "http://127.0.0.1:8001",
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

// Centralized API error handling
api.interceptors.response.use(
    (response) => response,
    (error) => {
        // Clear an invalid or expired token
        if (error.response?.status === 401) {
            localStorage.removeItem("access_token");

            // Redirect to login if not already there
            if (window.location.pathname !== "/login") {
                window.location.href = "/login";
            }
        }

        // Attach a consistent, user-friendly error message
        error.userMessage = normalizeApiError(error);

        return Promise.reject(error);
    }
);

export default api;
