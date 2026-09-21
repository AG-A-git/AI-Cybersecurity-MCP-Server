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

    // =====================================================
    // FETCH HISTORY
    // =====================================================

    const fetchHistory = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await api.get("/scans");

            console.log("Scan history:", response.data);

            setHistory(response.data || []);
        } catch (error) {
            console.error(
                "Failed to fetch scan history:",
                error
            );

            setError(
                error.userMessage ||
                error.response?.data?.detail ||
                "Failed to load scan history."
            );
        } finally {
            setLoading(false);
        }
    };

    // =====================================================
    // INITIAL LOAD
    // =====================================================

    useEffect(() => {
        fetchHistory();
    }, []);

    // =====================================================
    // SEARCH
    // =====================================================

    const filteredHistory = history.filter((item) => {
        const searchText =
            search.toLowerCase().trim();

        if (!searchText) {
            return true;
        }

        const projectName =
            item.project_name || "";

        const fileName =
            item.filename || "";

        const status =
            item.status || "";

        return (
            projectName
                .toLowerCase()
                .includes(searchText) ||
            fileName
                .toLowerCase()
                .includes(searchText) ||
            status
                .toLowerCase()
                .includes(searchText)
        );
    });

    // =====================================================
    // OPEN PROJECT
    // =====================================================

    const handleOpenProject = (projectId) => {
        localStorage.setItem(
            "selected_project_id",
            projectId
        );

        navigate("/upload");
    };

    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Scan History</h1>

                <LoadingState
                    message="Loading scan history..."
                />
            </div>
        );
    }

    // =====================================================
    // ERROR
    // =====================================================

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
            {/* HEADER */}

            <h1>Scan History</h1>

            <p>
                View your previous security scans.
            </p>

            <hr />

            {/* SEARCH */}

            <section
                style={{
                    marginTop: "25px",
                }}
            >
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

            {/* REFRESH */}

            <div
                style={{
                    marginTop: "20px",
                }}
            >
                <button
                    type="button"
                    onClick={fetchHistory}
                >
                    Refresh History
                </button>
            </div>

            {/* EMPTY */}

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
                    {/* RESULT COUNT */}

                    <p
                        style={{
                            marginTop: "30px",
                        }}
                    >
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

                    {/* NO SEARCH RESULTS */}

                    {filteredHistory.length === 0 ? (
                        <EmptyState
                            title="No matching scans"
                            message="Try a different search term."
                        />
                    ) : (
                        /* TABLE */

                        <div
                            style={{
                                marginTop: "20px",
                                overflowX: "auto",
                            }}
                        >
                            <table
                                style={{
                                    width: "100%",
                                    borderCollapse:
                                        "collapse",
                                }}
                            >
                                <thead>
                                    <tr>
                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
                                            #
                                        </th>

                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
                                            Project
                                        </th>

                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
                                            File
                                        </th>

                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
                                            Project ID
                                        </th>

                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
                                            Status
                                        </th>

                                        <th
                                            style={{
                                                textAlign:
                                                    "left",
                                                padding:
                                                    "12px",
                                                borderBottom:
                                                    "2px solid #ccc",
                                            }}
                                        >
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
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
                                                    {index + 1}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
                                                    {item.project_name ||
                                                        "Unknown Project"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
                                                    {item.filename ||
                                                        "Unknown File"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
                                                    {item.project_id ||
                                                        "N/A"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
                                                    {item.status ||
                                                        "Completed"}
                                                </td>

                                                <td
                                                    style={{
                                                        padding:
                                                            "12px",
                                                        borderBottom:
                                                            "1px solid #eee",
                                                    }}
                                                >
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