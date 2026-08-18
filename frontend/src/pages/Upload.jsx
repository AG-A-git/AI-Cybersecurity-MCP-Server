import React, { useState } from "react";
import api from "../services/api";

function Upload() {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [result, setResult] = useState(null);

    const handleFileChange = (event) => {
        const selectedFile = event.target.files?.[0] || null;

        setFile(selectedFile);
        setError("");
        setResult(null);
    };

    const getErrorMessage = (error) => {
        if (!error.response) {
            return "Could not connect to the backend server.";
        }

        const status = error.response.status;
        const data = error.response.data;

        // 401 - Authentication required
        if (status === 401) {
            return "Login required. Please log in again.";
        }

        // 403 - Not authorized
        if (status === 403) {
            return "You are not authorized to perform this action.";
        }

        // 404 - Resource not found
        if (status === 404) {
            return "Resource not found.";
        }

        // 422 - Validation error
        if (status === 422) {
            if (Array.isArray(data?.detail)) {
                return data.detail
                    .map((item) => {
                        if (typeof item === "string") {
                            return item;
                        }

                        if (item?.msg) {
                            const location = Array.isArray(item.loc)
                                ? item.loc.join(" → ")
                                : "";

                            return location
                                ? `${location}: ${item.msg}`
                                : item.msg;
                        }

                        return JSON.stringify(item);
                    })
                    .join("\n");
            }

            if (typeof data?.detail === "string") {
                return data.detail;
            }

            return "Invalid request. Please check the selected file.";
        }

        // 500 - Server error
        if (status === 500) {
            return (
                data?.detail ||
                "Server error. Please try again later."
            );
        }

        // Other backend errors
        if (typeof data?.detail === "string") {
            return data.detail;
        }

        return `Server error: ${status}`;
    };

    const handleUpload = async (event) => {
        event.preventDefault();

        if (!file) {
            setError("Please select a file first.");
            return;
        }

        setLoading(true);
        setError("");
        setResult(null);

        console.log("Starting security scan...");
        console.log("File:", file.name);

        try {
            const formData = new FormData();

            formData.append("file", file);

            console.log("Sending file to /upload");

            const response = await api.post(
                "/upload",
                formData
            );

            console.log("SCAN RESPONSE:", response.data);

            setResult(response.data);
        } catch (error) {
            console.error("Scan error:", error);

            setError(getErrorMessage(error));
        } finally {
            setLoading(false);
        }
    };

    const getSeverityIndicator = (severity) => {
        if (!severity) {
            return "⚪ Unknown";
        }

        const normalizedSeverity =
            severity.toLowerCase();

        switch (normalizedSeverity) {
            case "critical":
                return "🔴 Critical";

            case "high":
                return "🟠 High";

            case "medium":
                return "🟡 Medium";

            case "low":
                return "🟢 Low";

            default:
                return `⚪ ${severity}`;
        }
    };

    return (
        <div
            style={{
                padding: "40px",
                maxWidth: "900px",
                margin: "0 auto",
            }}
        >
            <h1>Security Scan</h1>

            <p>
                Upload a source-code file to scan for
                security vulnerabilities.
            </p>

            {/* Upload Section */}
            <form onSubmit={handleUpload}>
                <div
                    style={{
                        marginTop: "30px",
                        padding: "30px",
                        border: "1px solid #ddd",
                        borderRadius: "10px",
                    }}
                >
                    <input
                        type="file"
                        onChange={handleFileChange}
                        disabled={loading}
                    />

                    {file && (
                        <p>
                            Selected file:{" "}
                            <strong>{file.name}</strong>
                        </p>
                    )}

                    <button
                        type="submit"
                        disabled={!file || loading}
                        style={{
                            marginTop: "20px",
                            padding: "12px 25px",
                            cursor:
                                !file || loading
                                    ? "not-allowed"
                                    : "pointer",
                        }}
                    >
                        {loading
                            ? "Scanning..."
                            : "Upload & Scan"}
                    </button>
                </div>
            </form>

            {/* Error Message */}
            {error && (
                <div
                    style={{
                        marginTop: "25px",
                        padding: "15px",
                        border: "1px solid red",
                        borderRadius: "8px",
                        color: "red",
                        backgroundColor: "#fff5f5",
                        whiteSpace: "pre-wrap",
                    }}
                >
                    <strong>Error:</strong>

                    <div style={{ marginTop: "8px" }}>
                        {error}
                    </div>
                </div>
            )}

            {/* Scan Results */}
            {result && (
                <div
                    style={{
                        marginTop: "30px",
                        padding: "25px",
                        border: "1px solid #ddd",
                        borderRadius: "10px",
                    }}
                >
                    <h2>Scan Results</h2>

                    {/* File Information */}
                    <p>
                        <strong>File:</strong>{" "}
                        {result.filename}
                    </p>

                    <p>
                        <strong>
                            Total vulnerabilities:
                        </strong>{" "}
                        {result.total_vulnerabilities}
                    </p>

                    {/* Severity Summary */}
                    {result.summary && (
                        <div
                            style={{
                                marginTop: "20px",
                                padding: "20px",
                                border: "1px solid #ddd",
                                borderRadius: "8px",
                            }}
                        >
                            <h3>Severity Summary</h3>

                            <p>
                                🔴 <strong>Critical:</strong>{" "}
                                {result.summary.critical ?? 0}
                            </p>

                            <p>
                                🟠 <strong>High:</strong>{" "}
                                {result.summary.high ?? 0}
                            </p>

                            <p>
                                🟡 <strong>Medium:</strong>{" "}
                                {result.summary.medium ?? 0}
                            </p>

                            <p>
                                🟢 <strong>Low:</strong>{" "}
                                {result.summary.low ?? 0}
                            </p>
                        </div>
                    )}

                    {/* Vulnerability List */}
                    <h3
                        style={{
                            marginTop: "25px",
                        }}
                    >
                        Vulnerabilities
                    </h3>

                    {result.vulnerabilities &&
                    result.vulnerabilities.length > 0 ? (
                        result.vulnerabilities.map(
                            (item, index) => (
                                <div
                                    key={index}
                                    style={{
                                        marginTop: "15px",
                                        padding: "18px",
                                        border: "1px solid #ddd",
                                        borderRadius: "8px",
                                    }}
                                >
                                    {/* Severity */}
                                    <div
                                        style={{
                                            fontSize: "18px",
                                            fontWeight: "bold",
                                            marginBottom: "10px",
                                        }}
                                    >
                                        {getSeverityIndicator(
                                            item.severity
                                        )}
                                    </div>

                                    {/* Vulnerability Name */}
                                    <div
                                        style={{
                                            fontSize: "17px",
                                            fontWeight: "bold",
                                            marginBottom: "8px",
                                        }}
                                    >
                                        {item.vulnerability ||
                                            "Unknown vulnerability"}
                                    </div>

                                    {/* Description */}
                                    {item.description && (
                                        <div
                                            style={{
                                                marginBottom: "8px",
                                            }}
                                        >
                                            {item.description}
                                        </div>
                                    )}

                                    {/* File */}
                                    {item.file && (
                                        <div>
                                            <strong>
                                                File:
                                            </strong>{" "}
                                            {item.file}
                                        </div>
                                    )}

                                    {/* Line */}
                                    {item.line && (
                                        <div>
                                            <strong>
                                                Line:
                                            </strong>{" "}
                                            {item.line}
                                        </div>
                                    )}

                                    {/* Confidence */}
                                    {item.confidence && (
                                        <div>
                                            <strong>
                                                Confidence:
                                            </strong>{" "}
                                            {item.confidence}
                                        </div>
                                    )}

                                    {/* Status */}
                                    {item.status && (
                                        <div
                                            style={{
                                                marginTop: "8px",
                                            }}
                                        >
                                            <strong>
                                                Status:
                                            </strong>{" "}
                                            {item.status}
                                        </div>
                                    )}
                                </div>
                            )
                        )
                    ) : (
                        <p>
                            No vulnerabilities were detected.
                        </p>
                    )}
                </div>
            )}
        </div>
    );
}

export default Upload;