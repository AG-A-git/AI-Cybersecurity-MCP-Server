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

        const data = error.response.data;

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

        return `Server error: ${error.response.status}`;
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
                        }}
                    >
                        {loading
                            ? "Scanning..."
                            : "Upload & Scan"}
                    </button>
                </div>
            </form>

            {error && (
                <div
                    style={{
                        marginTop: "25px",
                        padding: "15px",
                        border: "1px solid red",
                        borderRadius: "8px",
                        color: "red",
                        whiteSpace: "pre-wrap",
                    }}
                >
                    {error}
                </div>
            )}

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

                    <p>
                        <strong>File:</strong>{" "}
                        {result.filename}
                    </p>

                    <p>
                        <strong>Total vulnerabilities:</strong>{" "}
                        {result.total_vulnerabilities}
                    </p>

                    {result.summary && (
                        <div>
                            <p>
                                Critical:{" "}
                                {result.summary.critical}
                            </p>

                            <p>
                                High:{" "}
                                {result.summary.high}
                            </p>

                            <p>
                                Medium:{" "}
                                {result.summary.medium}
                            </p>

                            <p>
                                Low:{" "}
                                {result.summary.low}
                            </p>
                        </div>
                    )}

                    <h3>Vulnerabilities</h3>

                    {result.vulnerabilities?.map(
                        (item, index) => (
                            <div
                                key={index}
                                style={{
                                    marginTop: "15px",
                                    padding: "15px",
                                    border: "1px solid #ddd",
                                    borderRadius: "8px",
                                }}
                            >
                                <strong>
                                    {item.severity}
                                </strong>

                                <div>
                                    {item.vulnerability}
                                </div>

                                <div>
                                    {item.description}
                                </div>

                                <div>
                                    Status: {item.status}
                                </div>
                            </div>
                        )
                    )}
                </div>
            )}
        </div>
    );
}

export default Upload;