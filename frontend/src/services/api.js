import axios from "axios";

const API_URL = "http://127.0.0.1:8000";

const api = axios.create({
    baseURL: API_URL,
});

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("token");

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        return config;
    },
    (error) => Promise.reject(error)
);


// =========================
// LOGIN
// =========================

export const login = async (email, password) => {
    const response = await api.post("/login", {
        email,
        password,
    });

    if (response.data?.access_token) {
    localStorage.setItem(
        "token",
        response.data.access_token
    );
}

    return response.data;
};


// =========================
// REGISTER
// =========================

export const register = async (
    username,
    email,
    password
) => {
    const response = await api.post("/register", {
        username,
        email,
        password,
    });

    return response.data;
};


// =========================
// DASHBOARD
// =========================

export const getDashboard = async () => {
    const response = await api.get("/dashboard");

    return response.data;
};


// =========================
// PROFILE
// =========================

export const getProfile = async () => {
    const response = await api.get("/profile");

    return response.data;
};


// =========================
// UPLOAD
// =========================

export const uploadFile = async (file) => {
    const formData = new FormData();

    formData.append("file", file);

    const response = await api.post(
        "/upload",
        formData
    );

    return response.data;
};


// =========================
// LOGOUT
// =========================

export const logout = () => {
    localStorage.removeItem("token");
};


// =========================
// DEFAULT EXPORT
// =========================

export default api;