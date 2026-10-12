
import api from "./api";

export const uploadFile = (projectId, file) => {
    const formData = new FormData();

    formData.append("file", file);

    return api.post("/upload/", formData, {
        params: {
            project_id: Number(projectId),
        },
    });
};
