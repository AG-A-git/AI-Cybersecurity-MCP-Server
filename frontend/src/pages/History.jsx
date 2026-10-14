import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getProjects } from "../services/projectService";
import { getScans, getScanResults } from "../services/scanService";
import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

function getList(response, keys = []) {
    if (Array.isArray(response)) return response;

    for (const key of keys) {
        if (Array.isArray(response?.[key])) {
            return response[key];
        }
    }

    if (Array.isArray(response?.data)) {
        return response.data;
    }

    return [];
}

function getFindingCount(scan) {
    const rawCount =
        scan.vulnerability_count ??
        scan.total_vulnerabilities;

    if (rawCount === null || rawCount === undefined || rawCount === "") {
        return "Not available";
    }

    const count = Number(rawCount);

    return Number.isFinite(count) && count >= 0
        ? count
        : "Not available";
}

function getScanStatus(scan) {
    return scan.status ?? scan.state ?? "Unknown";
}

function History() {
    const navigate = useNavigate();

    const [scans, setScans] = useState([]);
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("All");
    const [openingScanId, setOpeningScanId] = useState(null);
    const [openError, setOpenError] = useState("");

    const loadHistory = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] =
                await Promise.allSettled([
                    getProjects(),
                    getScans(),
                ]);

            if (projectsResult.status === "fulfilled") {
                setProjects(
                    getList(projectsResult.value, ["projects"])
                );
            } else {
                console.error(
                    "Failed to load projects:",
                    projectsResult.reason
                );
                setProjects([]);
            }

            if (scansResult.status === "fulfilled") {
                setScans(
                    getList(scansResult.value, ["scans"])
                );
            } else {
                console.error(
                    "Failed to load scans:",
                    scansResult.reason
                );

                throw scansResult.reason;
            }
        } catch (err) {
            console.error("History loading error:", err);

            setError(
                err.userMessage ||
                err.response?.data?.detail ||
                err.message ||
                "Unable to load scan history. Please try again."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadHistory();
    }, [loadHistory]);

    const getProjectName = useCallback(
        (scan) => {
            const projectId = scan.project_id ?? scan.projectId;

            const project = projects.find(
                (item) => String(item.id) === String(projectId)
            );

            return (
                scan.project_name ||
                project?.project_name ||
                project?.name ||
                (projectId != null
                    ? `Project ${projectId}`
                    : "Unknown project")
            );
        },
        [projects]
    );

    const filteredScans = useMemo(() => {
        const query = searchTerm.trim().toLowerCase();

        return scans.filter((scan) => {
            const projectName = getProjectName(scan);
            const scanId = scan.scan_id ?? scan.id ?? "";
            const projectId = scan.project_id ?? scan.projectId ?? "";
            const status = getScanStatus(scan);

            const matchesSearch = [
                projectName,
                scanId,
                projectId,
                status,
            ]
                .join(" ")
                .toLowerCase()
                .includes(query);

            const matchesStatus =
                statusFilter === "All" ||
                status.toLowerCase() === statusFilter.toLowerCase();

            return matchesSearch && matchesStatus;
        });
    }, [scans, searchTerm, statusFilter, getProjectName]);

    const statusOptions = useMemo(
        () => [
            ...new Set(scans.map((scan) => getScanStatus(scan))),
        ].sort(),
        [scans]
    );

    const handleViewResults = async (scan) => {
        const scanId = scan.scan_id ?? scan.id;

        setOpenError("");

        if (scanId == null) {
            setOpenError(
                "This history record does not contain a scan ID."
            );
            return;
        }

        setOpeningScanId(String(scanId));

        try {
            const result = await getScanResults(scanId);

            sessionStorage.setItem(
                "last_scan_data",
                JSON.stringify({
                    scanId,
                    result,
                })
            );

            navigate("/results", {
                state: {
                    scanId,
                    result,
                },
            });
        } catch (err) {
            console.error("Failed to open scan results:", err);

            setOpenError(
                err.userMessage ||
                err.response?.data?.detail ||
                "Could not open this scan's results. Please try again."
            );
        } finally {
            setOpeningScanId(null);
        }
    };

    if (loading) {
        return (
            <main className="p-4 sm:p-6">
                <h1 className="text-2xl font-bold">Scan History</h1>
                <LoadingState message="Loading history..." />
            </main>
        );
    }

    if (error) {
        return (
            <main className="p-4 sm:p-6">
                <h1 className="text-2xl font-bold">Scan History</h1>
                <ErrorState
                    message={error}
                    onRetry={loadHistory}
                />
            </main>
        );
    }

    return (
        <main className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6">
            <header className="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h1 className="text-2xl font-bold">
                        Scan History
                    </h1>

                    <p className="mt-1 text-gray-600">
                        Review previous scans for your cybersecurity projects.
                    </p>
                </div>

                <button
                    type="button"
                    onClick={loadHistory}
                    disabled={loading}
                    className="rounded-lg border border-gray-300 px-4 py-2 disabled:opacity-50"
                >
                    {loading ? "Refreshing..." : "Refresh History"}
                </button>
            </header>

            <section className="rounded-xl border border-gray-200 bg-white p-5">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <label className="text-sm font-medium">
                        Search history

                        <input
                            type="search"
                            value={searchTerm}
                            onChange={(event) =>
                                setSearchTerm(event.target.value)
                            }
                            placeholder="Search project, scan ID, or status"
                            className="mt-1 block w-full rounded-lg border p-2"
                        />
                    </label>

                    <label className="text-sm font-medium">
                        Filter by status

                        <select
                            value={statusFilter}
                            onChange={(event) =>
                                setStatusFilter(event.target.value)
                            }
                            className="mt-1 block w-full rounded-lg border p-2"
                        >
                            <option value="All">All statuses</option>

                            {statusOptions.map((status) => (
                                <option key={status} value={status}>
                                    {status}
                                </option>
                            ))}
                        </select>
                    </label>
                </div>

                <p className="mt-3 text-sm text-gray-600">
                    Showing {filteredScans.length} of {scans.length} scans
                </p>
            </section>

            {openError && (
                <div
                    role="alert"
                    className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700"
                >
                    {openError}
                </div>
            )}

            {scans.length === 0 ? (
                <EmptyState
                    title="No scan history yet"
                    message="Upload a source file and start a scan to see scan records here."
                />
            ) : filteredScans.length === 0 ? (
                <section className="rounded-xl border border-gray-200 bg-white p-5">
                    <p>No scans match your search or status filter.</p>

                    <button
                        type="button"
                        onClick={() => {
                            setSearchTerm("");
                            setStatusFilter("All");
                        }}
                        className="mt-3 rounded-lg border border-gray-300 px-4 py-2"
                    >
                        Reset Filters
                    </button>
                </section>
            ) : (
                <section className="grid grid-cols-1 gap-4">
                    {filteredScans.map((scan, index) => {
                        const scanId = scan.scan_id ?? scan.id;
                        const projectId =
                            scan.project_id ?? scan.projectId;
                        const status = getScanStatus(scan);
                        const createdAt =
                            scan.created_at ?? scan.started_at;

                        return (
                            <article
                                key={scanId ?? `scan-${index}`}
                                className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm"
                            >
                                <div className="flex flex-wrap items-start justify-between gap-3">
                                    <div>
                                        <h2 className="text-lg font-semibold">
                                            {getProjectName(scan)}
                                        </h2>

                                        <p className="mt-1 text-sm text-gray-600">
                                            Scan ID: {scanId ?? "Not available"}
                                        </p>
                                    </div>

                                    <span className="rounded-full border border-gray-200 px-3 py-1 text-sm">
                                        {status}
                                    </span>
                                </div>

                                <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
                                    <p>
                                        <strong>Project ID:</strong>{" "}
                                        {projectId ?? "Not available"}
                                    </p>

                                    <p>
                                        <strong>Findings:</strong>{" "}
                                        {getFindingCount(scan)}
                                    </p>

                                    <p>
                                        <strong>Scan date:</strong>{" "}
                                        {createdAt
                                            ? new Date(
                                                  createdAt
                                              ).toLocaleString()
                                            : "Not available"}
                                    </p>
                                </div>

                                <button
                                    type="button"
                                    onClick={() => handleViewResults(scan)}
                                    disabled={
                                        scanId == null ||
                                        openingScanId === String(scanId)
                                    }
                                    className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-white disabled:cursor-not-allowed disabled:opacity-50"
                                >
                                    {openingScanId === String(scanId)
                                        ? "Opening Results..."
                                        : "View Scan Results"}
                                </button>
                            </article>
                        );
                    })}
                </section>
            )}
        </main>
    );
}

export default History;