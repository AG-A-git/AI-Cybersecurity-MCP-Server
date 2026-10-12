
export const normalizeApiError = (error) => {
    if (!error?.response) {
        return "Backend unavailable. Please check your connection and try again.";
    }

    const status = error.response.status;

    switch (status) {
        case 400:
            return "Invalid request. Please check your input.";

        case 401:
            return "Authentication required. Please login again.";

        case 403:
            return "Access denied.";

        case 404:
            return "The requested resource was not found.";

        case 422:
            return "Validation failed. Please check the submitted data.";

        case 500:
            return "Server error. Please try again later.";

        default:
            return "Something went wrong. Please try again.";
    }
};
