import { useEffect, useState } from "react";
import { getScans } from "../services/scanService";
import ScanStatus from "../components/ScanStatus";

function History() {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const loadScans = async () => {
            try {
                setLoading(true);
                setError("");

                const response = await getScans();

                setScans(
                    Array.isArray(response.data)
                        ? response.data
                        : []
                );
            } catch (err) {
                console.error(
                    "Scan history error:",
                    err
                );

                setError(
                    err.userMessage ||
                    "Unable to load scan history."
                );
            } finally {
                setLoading(false);
            }
        };

        loadScans();
    }, []);

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Scan History</h1>
                <p>Loading scan history...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Scan History</h1>

                <p style={{ color: "red" }}>
                    {error}
                </p>
            </div>
        );
    }

    return (
        <div style={{ padding: "30px" }}>
            <h1>Scan History</h1>

            <p>
                View your previous security scans.
            </p>

            {scans.length === 0 ? (
                <div
                    style={{
                        marginTop: "25px",
                        border: "1px solid #ccc",
                        borderRadius: "8px",
                        padding: "20px",
                    }}
                >
                    <h2>No scans yet</h2>

                    <p>
                        Upload a source file from a project
                        to start your first security scan.
                    </p>
                </div>
            ) : (
                <div
                    style={{
                        marginTop: "25px",
                        display: "grid",
                        gap: "15px",
                    }}
                >
                    {scans.map((scan, index) => (
                        <div
                            key={
                                scan.id ??
                                `${scan.project_id}-${index}`
                            }
                            style={{
                                border: "1px solid #ccc",
                                borderRadius: "8px",
                                padding: "20px",
                            }}
                        >
                            <h2>
                                {scan.project_name ||
                                    "Unknown Project"}
                            </h2>

                            <p>
                                <strong>
                                    File:
                                </strong>{" "}
                                {scan.filename ||
                                    "Not available"}
                            </p>

                            <p>
                                <strong>
                                    Project ID:
                                </strong>{" "}
                                {scan.project_id ??
                                    "Not available"}
                            </p>

                            <p>
                                <strong>
                                    Scan ID:
                                </strong>{" "}
                                {scan.id ??
                                    "Not available"}
                            </p>

                            <div
                                style={{
                                    marginTop: "15px",
                                }}
                            >
                                <strong>
                                    Status
                                </strong>

                                <div
                                    style={{
                                        marginTop: "8px",
                                    }}
                                >
                                    <ScanStatus
                                        status={
                                            scan.status
                                        }
                                    />
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default History;