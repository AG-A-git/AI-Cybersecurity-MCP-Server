import axios from "axios";

const api = axios.create({
  baseURL: "http://127.0.0.1:8000",
  headers: {
    "Content-Type": "application/json",
  },
});

// Login
export const login = async (data) => {
  return api.post("/login", data);
};

// Register
export const register = async (data) => {
  return api.post("/register", data);
};

// Upload file
export const uploadFile = async (file) => {
  const formData = new FormData();
  formData.append("file", file);

  return api.post("/upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });
};

// Get scan history
export const getHistory = async () => {
  return api.get("/history");
};

// Get reports
export const getReports = async () => {
  return api.get("/reports");
};

export default api;