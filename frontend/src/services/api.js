import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:8000",
});

// Add JWT token automatically to every request
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("access_token");

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Centralized API error handling
api.interceptors.response.use(
    (response) => {
        return response;
    },
    (error) => {
        if (error.response) {
            switch (error.response.status) {
                case 400:
                    error.userMessage = "Invalid request.";
                    break;

                case 401:
                    error.userMessage = "Please login again.";
                    localStorage.removeItem("access_token");
                    break;

                case 403:
                    error.userMessage = "Access denied.";
                    break;

                case 404:
                    error.userMessage = "Resource not found.";
                    break;

                case 500:
                    error.userMessage =
                        "Server error. Please try again later.";
                    break;

                default:
                    error.userMessage =
                        "Something went wrong. Please try again.";
            }
        } else {
            error.userMessage =
                "Backend unavailable. Please try again.";
        }

        return Promise.reject(error);
    }
);

export default api;