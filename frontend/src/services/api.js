import axios from "axios";
import { normalizeApiError } from "../utils/apiError";

const api = axios.create({
    baseURL: "http://127.0.0.1:8002",
});

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("access_token");

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        if (config.data instanceof FormData) {
            delete config.headers["Content-Type"];
        }

        return config;
    },
    (error) => Promise.reject(error)
);

api.interceptors.response.use(
    (response) => response,
    (error) => {
        const status = error.response?.status;
        const requestUrl = error.config?.url || "";
        const isAuthRequest = /^\/?(login|register)(\/|$)/i.test(requestUrl);

        if (status === 401 && !isAuthRequest) {
            localStorage.removeItem("access_token");
            localStorage.removeItem("selected_project_id");

            if (window.location.pathname !== "/login") {
                window.location.replace("/login");
            }
        }

        error.userMessage = normalizeApiError(error);
        return Promise.reject(error);
    }
);

export default api;
