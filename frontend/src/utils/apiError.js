export const normalizeApiError = (error) => {
    // Request timed out
    if (error?.code === "ECONNABORTED") {
        return "The request timed out. Please try again.";
    }

    // Backend is unreachable or the network request failed
    if (!error?.response) {
        return "Unable to connect to the backend. Check that the server is running and try again.";
    }

    const status = error.response.status;
    const detail = error.response.data?.detail;

    switch (status) {
        case 400:
            return typeof detail === "string"
                ? detail
                : "Invalid request. Please check your input.";

        case 401:
            return "Your session has expired. Please log in again.";

        case 403:
            return "You do not have permission to perform this action.";

        case 404:
            return "The requested resource was not found.";

        case 409:
            return typeof detail === "string"
                ? detail
                : "This request conflicts with existing data.";

        case 422:
            return typeof detail === "string"
                ? detail
                : "Validation failed. Please check the submitted data.";

        default:
            if (status >= 500) {
                return "A server error occurred. Please try again later.";
            }

            return "Something went wrong. Please try again.";
    }
};