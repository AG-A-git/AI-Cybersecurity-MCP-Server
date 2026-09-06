import React, { useState } from "react";
import api from "../services/api";

function Upload() {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [result, setResult] = useState(null);

    // Scan status
    const [scanStatus, setScanStatus] = useState("idle");

    const handleFileChange = (event) => {
        const selectedFile = event.target.files?.[0] || null;

        setFile(selectedFile);
        setError("");
        setResult(null);
        setScanStatus("idle");
    };

    const getErrorMessage = (error) => {
        if (!error.response) {
            return "Could not connect to the backend server.";
        }

        const status = error.response.status;
        const data = error.response.data;

        if (status === 401) {
            return "Login required. Please log in again.";
        }

        if (status === 403) {
            return "You are not authorized to perform this action.";
        }

        if (status === 404) {
            return "Resource not found.";
        }

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

        if (status === 500) {
            return (
                data?.detail ||
                "Server error. Please try again later."
            );
        }

        if (typeof data?.detail === "string") {
            return data.detail;
        }

        return `Server error: ${status}`;
    };

    const handleUpload = async (event) => {
        event.preventDefault();

        if (!file) {
            setError("Please select a file first.");
            setScanStatus("failed");
            return;
        }

        setLoading(true);
        setError("");
        setResult(null);

        // Start scanning
        setScanStatus("scanning");

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

            // Save actual backend result
            setResult(response.data);

            // Scan completed successfully
            setScanStatus("completed");

        } catch (error) {
            console.error("Scan error:", error);

            // Scan failed
            setScanStatus("failed");

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

    const getLanguage = (filename) => {
        if (!filename) {
            return "Unknown";
        }

        const extension =
            filename.split(".").pop()?.toLowerCase();

        switch (extension) {
            case "py":
                return "Python";

            case "js":
                return "JavaScript";

            case "jsx":
                return "React / JavaScript";

            case "java":
                return "Java";

            case "cpp":
                return "C++";

            case "c":
                return "C";

            case "php":
                return "PHP";

            case "ts":
                return "TypeScript";

            case "tsx":
                return "React / TypeScript";

            default:
                return "Unknown";
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

            {/* Scan Status */}
            <div
                style={{
                    marginTop: "25px",
                    padding: "20px",
                    border: "1px solid #ddd",
                    borderRadius: "8px",
                }}
            >
                <h3>Scan Status</h3>

                {scanStatus === "idle" && (
                    <p>⚪ Ready to scan</p>
                )}

                {scanStatus === "scanning" && (
                    <p>
                        🔄 <strong>Scanning...</strong>
                        <br />
                        Please wait while the backend
                        analyzes your file.
                    </p>
                )}

                {scanStatus === "completed" && (
                    <p>
                        ✅ <strong>Scan Completed</strong>
                    </p>
                )}

                {scanStatus === "failed" && (
                    <p>
                        ❌ <strong>Scan Failed</strong>
                    </p>
                )}
            </div>

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
                    <div
                        style={{
                            marginTop: "20px",
                            padding: "20px",
                            border: "1px solid #ddd",
                            borderRadius: "8px",
                        }}
                    >
                        <h3>File Information</h3>

                        <p>
                            <strong>File Name:</strong>{" "}
                            {result.filename}
                        </p>

                        <p>
                            <strong>Language:</strong>{" "}
                            {getLanguage(result.filename)}
                        </p>

                        <p>
                            <strong>File Size:</strong>{" "}
                            {result.file_size} bytes
                        </p>

                        <p>
                            <strong>Uploaded By:</strong>{" "}
                            {result.uploaded_by}
                        </p>

                        <p>
                            <strong>Status:</strong>{" "}
                            {scanStatus === "completed"
                                ? "Scan Completed"
                                : scanStatus === "failed"
                                ? "Scan Failed"
                                : "Scanning..."}
                        </p>
                    </div>

                    {/* Total Vulnerabilities */}
                    <p style={{ marginTop: "20px" }}>
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
                                🔴{" "}
                                <strong>Critical:</strong>{" "}
                                {result.summary.critical ?? 0}
                            </p>

                            <p>
                                🟠{" "}
                                <strong>High:</strong>{" "}
                                {result.summary.high ?? 0}
                            </p>

                            <p>
                                🟡{" "}
                                <strong>Medium:</strong>{" "}
                                {result.summary.medium ?? 0}
                            </p>

                            <p>
                                🟢{" "}
                                <strong>Low:</strong>{" "}
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