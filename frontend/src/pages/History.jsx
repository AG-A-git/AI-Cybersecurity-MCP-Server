import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function History() {
    const navigate = useNavigate();

    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [search, setSearch] = useState("");

    const fetchHistory = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await api.get("/scans");

            console.log("Scan history:", response.data);

            setHistory(Array.isArray(response.data) ? response.data : []);
        } catch (error) {
            console.error("Failed to fetch scan history:", error);

            setError(
                error.userMessage ||
                error.response?.data?.detail ||
                "Failed to load scan history."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchHistory();
    }, []);

    const filteredHistory = history.filter((item) => {
        const searchText = search.toLowerCase().trim();

        if (!searchText) {
            return true;
        }

        const projectName = item.project_name || "";
        const fileName = item.filename || "";
        const status = item.status || "";

        return (
            projectName.toLowerCase().includes(searchText) ||
            fileName.toLowerCase().includes(searchText) ||
            status.toLowerCase().includes(searchText)
        );
    });

    const handleOpenProject = (projectId) => {
        localStorage.setItem(
            "selected_project_id",
            String(projectId)
        );

        navigate("/upload");
    };

    const handleViewResults = (item) => {
        /*
         * The /scans API currently returns only:
         * id, project_id, project_name, filename, status.
         *
         * Therefore we do not invent vulnerability/risk data here.
         *
         * Open the project so the user can continue the workflow.
         */
        localStorage.setItem(
            "selected_project_id",
            String(item.project_id)
        );

        navigate("/upload");
    };

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Scan History</h1>

                <LoadingState message="Loading scan history..." />
            </div>
        );
    }

    if (error) {
        return (
            <div
                style={{
                    padding: "30px",
                    maxWidth: "1000px",
                    margin: "0 auto",
                }}
            >
                <h1>Scan History</h1>

                <ErrorState
                    message={error}
                    onRetry={fetchHistory}
                />
            </div>
        );
    }

    return (
        <div
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            <h1>Scan History</h1>

            <p>
                View your previous security scans.
            </p>

            <hr />

            {/* Search */}
            <section style={{ marginTop: "25px" }}>
                <label htmlFor="historySearch">
                    <strong>Search scans</strong>
                </label>

                <br />

                <input
                    id="historySearch"
                    type="text"
                    value={search}
                    onChange={(e) =>
                        setSearch(e.target.value)
                    }
                    placeholder="Search by project, file or status..."
                    style={{
                        width: "100%",
                        maxWidth: "500px",
                        padding: "10px",
                        marginTop: "8px",
                    }}
                />
            </section>

            {/* Refresh */}
            <div style={{ marginTop: "20px" }}>
                <button
                    type="button"
                    onClick={fetchHistory}
                >
                    Refresh History
                </button>
            </div>

            {/* No history */}
            {history.length === 0 ? (
                <EmptyState
                    title="No scans found"
                    message="You have not uploaded or scanned any files yet."
                    buttonText="Go to Projects"
                    onButtonClick={() =>
                        navigate("/projects")
                    }
                />
            ) : (
                <>
                    <p style={{ marginTop: "30px" }}>
                        Showing{" "}
                        <strong>
                            {filteredHistory.length}
                        </strong>{" "}
                        of{" "}
                        <strong>
                            {history.length}
                        </strong>{" "}
                        scans.
                    </p>

                    {filteredHistory.length === 0 ? (
                        <EmptyState
                            title="No matching scans"
                            message="Try a different search term."
                        />
                    ) : (
                        <div
                            style={{
                                marginTop: "20px",
                                overflowX: "auto",
                            }}
                        >
                            <table
                                style={{
                                    width: "100%",
                                    borderCollapse: "collapse",
                                }}
                            >
                                <thead>
                                    <tr>
                                        <th style={{ padding: "10px" }}>
                                            #
                                        </th>

                                        <th style={{ padding: "10px" }}>
                                            Scan ID
                                        </th>

                                        <th style={{ padding: "10px" }}>
                                            Project
                                        </th>

                                        <th style={{ padding: "10px" }}>
                                            File
                                        </th>

                                        <th style={{ padding: "10px" }}>
                                            Status
                                        </th>

                                        <th style={{ padding: "10px" }}>
                                            Action
                                        </th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {filteredHistory.map(
                                        (item, index) => (
                                            <tr
                                                key={
                                                    item.id ||
                                                    index
                                                }
                                            >
                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {index + 1}
                                                </td>

                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    #{item.id}
                                                </td>

                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {item.project_name ||
                                                        "Unknown Project"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {item.filename ||
                                                        "Unknown File"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {item.status ||
                                                        "Unknown"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding: "10px",
                                                    }}
                                                >
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            handleViewResults(
                                                                item
                                                            )
                                                        }
                                                    >
                                                        View Results
                                                    </button>

                                                    {" "}

                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            handleOpenProject(
                                                                item.project_id
                                                            )
                                                        }
                                                    >
                                                        Open Project
                                                    </button>
                                                </td>
                                            </tr>
                                        )
                                    )}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

export default History;