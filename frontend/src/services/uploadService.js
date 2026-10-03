import api from "./api";

export const uploadFile = (
    projectId,
    file
) => {
    const formData = new FormData();

    formData.append(
        "project_id",
        projectId
    );

    formData.append(
        "file",
        file
    );

    return api.post(
        "/upload",
        formData
    );
};