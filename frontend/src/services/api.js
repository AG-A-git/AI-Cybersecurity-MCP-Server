import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:8000",
});

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("access_token");

        if (token) {
            config.headers = config.headers || {};
            config.headers.Authorization = `Bearer ${token}`;
        }

        // Let Axios/browser set multipart/form-data headers.
        if (config.data instanceof FormData) {
            delete config.headers["Content-Type"];
        }

        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

export default api;