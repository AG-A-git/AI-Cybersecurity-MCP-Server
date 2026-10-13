
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import api from "../services/api";
import RiskSummary from "../components/RiskSummary";
import FindingCard from "../components/FindingCard";
import { normalizeVulnerability } from "../utils/vulnerabilityUtils";
import { deduplicateFindings } from "../utils/duplicateFindings";

const STORAGE_KEY = "last_scan_data";

const getFindings = (data) => {
    if (Array.isArray(data?.vulnerabilities)) return data.vulnerabilities;
    if (Array.isArray(data?.findings)) return data.findings;
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.results?.vulnerabilities)) {
        return data.results.vulnerabilities;
    }
    return [];
};

const getSeverityRank = (severity) => {
    const ranks = { critical: 4, high: 3, medium: 2, low: 1 };
    return ranks[String(severity ?? "").toLowerCase()] ?? 0;
};

const getVulnerabilityType = (item) =>
    item.vulnerability_type || item.vulnerability || item.type || "Unknown";

function ScanResults() {
    const location = useLocation();
    const navigate = useNavigate();
    const { scanId: routeScanId } = useParams();

    const initialState = useMemo(() => {
        if (location.state?.result) {
            const result = location.state.result;
            return {
                scanId: location.state.scanId ?? result.scan_id ?? result.id ?? null,
                result,
            };
        }

        try {
            const saved = sessionStorage.getItem(STORAGE_KEY);
            return saved
                ? JSON.parse(saved)
                : { scanId: null, result: null };
        } catch {
            return { scanId: null, result: null };
        }
    }, [location.state]);

    const scanId = routeScanId ?? initialState.scanId;

    const [result, setResult] = useState(initialState.result);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [severityFilter, setSeverityFilter] = useState("All");
    const [typeFilter, setTypeFilter] = useState("All");
    const [sortOrder, setSortOrder] = useState("severity-high");

    const resultRef = useRef(result);
    const requestNumber = useRef(0);

    useEffect(() => {
        resultRef.current = result;
    }, [result]);

    const loadScanResults = useCallback(async () => {
        if (!scanId) {
            if (!resultRef.current) {
                setError(
                    "No scan ID was found. Return to Upload and start a scan."
                );
            }
            return;
        }

        const currentRequest = ++requestNumber.current;
        setLoading(true);
        setError("");

        try {
            const response = await api.get(`/scans/${scanId}`);
            const data = response.data;

            if (currentRequest !== requestNumber.current) return;

            resultRef.current = data;
            setResult(data);

            sessionStorage.setItem(
                STORAGE_KEY,
                JSON.stringify({ scanId, result: data })
            );
        } catch (err) {
            if (currentRequest !== requestNumber.current) return;

            console.error("Failed to load scan results:", err);

            if (resultRef.current && getFindings(resultRef.current).length > 0) {
                setError("");
            } else {
                setError(
                    err.response?.data?.detail ??
                        err.userMessage ??
                        "Could not load scan results. Please try again."
                );
            }
        } finally {
            if (currentRequest === requestNumber.current) {
                setLoading(false);
            }
        }
    }, [scanId]);

    useEffect(() => {
        if (location.state?.result && location.state?.scanId) {
            resultRef.current = location.state.result;
            setResult(location.state.result);

            sessionStorage.setItem(
                STORAGE_KEY,
                JSON.stringify({
                    scanId: location.state.scanId,
                    result: location.state.result,
                })
            );
        }

        loadScanResults();

        return () => {
            requestNumber.current += 1;
        };
    }, [scanId, loadScanResults]);

    // Normalize the backend data, then remove duplicate findings.
    const vulnerabilities = useMemo(() => {
        const normalizedFindings = getFindings(result).map((item) =>
            normalizeVulnerability(item, result)
        );

        return deduplicateFindings(normalizedFindings);
    }, [result]);

    // Calculate severity counts from unique findings.
    const summary = useMemo(() => {
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        vulnerabilities.forEach((item) => {
            const severity = String(item.severity ?? "").toLowerCase();

            if (Object.prototype.hasOwnProperty.call(counts, severity)) {
                counts[severity] += 1;
            }
        });

        return counts;
    }, [vulnerabilities]);

    const vulnerabilityTypes = useMemo(
        () =>
            [...new Set(vulnerabilities.map(getVulnerabilityType))].sort(),
        [vulnerabilities]
    );

    const sortedVulnerabilities = useMemo(() => {
        const filtered = vulnerabilities.filter((item) => {
            const severityMatches =
                severityFilter === "All" ||
                String(item.severity ?? "").toLowerCase() ===
                    severityFilter.toLowerCase();

            const typeMatches =
                typeFilter === "All" ||
                getVulnerabilityType(item) === typeFilter;

            return severityMatches && typeMatches;
        });

        return [...filtered].sort((a, b) => {
            const rankA = getSeverityRank(a.severity);
            const rankB = getSeverityRank(b.severity);

            switch (sortOrder) {
                case "severity-low":
                    return rankA - rankB;

                case "risk-high":
                    return (
                        (Number(b.risk_score) || 0) -
                        (Number(a.risk_score) || 0)
                    );

                case "risk-low":
                    return (
                        (Number(a.risk_score) || 0) -
                        (Number(b.risk_score) || 0)
                    );

                case "file-az":
                    return (a.file_name || a.filename || "").localeCompare(
                        b.file_name || b.filename || ""
                    );

                case "file-za":
                    return (b.file_name || b.filename || "").localeCompare(
                        a.file_name || a.filename || ""
                    );

                case "line-low":
                    return (
                        (Number(a.line_number) || 0) -
                        (Number(b.line_number) || 0)
                    );

                case "line-high":
                    return (
                        (Number(b.line_number) || 0) -
                        (Number(a.line_number) || 0)
                    );

                case "severity-high":
                default:
                    return rankB - rankA;
            }
        });
    }, [vulnerabilities, severityFilter, typeFilter, sortOrder]);

    const handleViewDetails = (vulnerability) => {
        navigate("/vulnerability-details", {
            state: {
                vulnerability,
                finding: vulnerability,
                scanId,
                projectId: result?.project_id,
                fileName:
                    vulnerability.file_name ||
                    vulnerability.filename ||
                    result?.filename,
            },
        });
    };

    const handleResetFilters = () => {
        setSeverityFilter("All");
        setTypeFilter("All");
        setSortOrder("severity-high");
    };

    if (loading && !result) {
        return (
            <main className="p-6">
                <p role="status" className="text-gray-600">
                    Loading scan results...
                </p>
            </main>
        );
    }

    return (
        <main className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6">
            <header className="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">
                        Scan Results
                    </h1>
                    <p className="mt-1 text-sm text-gray-600">
                        Security analysis results from your scan.
                    </p>
                </div>

                <button
                    type="button"
                    onClick={loadScanResults}
                    disabled={loading}
                    className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium disabled:opacity-50"
                >
                    {loading ? "Refreshing..." : "Refresh Results"}
                </button>
            </header>

            {error && (
                <div
                    role="alert"
                    className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700"
                >
                    <p>{error}</p>
                    <button
                        type="button"
                        onClick={loadScanResults}
                        className="mt-2 font-semibold underline"
                    >
                        Try again
                    </button>
                </div>
            )}

            {result && (
                <>
                    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                        <h2 className="mb-3 text-lg font-semibold">
                            Scan Information
                        </h2>
                        <p>Scan ID: {result.id ?? scanId ?? "N/A"}</p>
                        <p>Project ID: {result.project_id ?? "N/A"}</p>
                        <p>Status: {result.status ?? "Unknown"}</p>

                        {result.created_at && (
                            <p>
                                Created:{" "}
                                {new Date(result.created_at).toLocaleString()}
                            </p>
                        )}

                        <p>Total vulnerabilities: {vulnerabilities.length}</p>
                    </section>

                    <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        {[
                            ["Critical", summary.critical, "text-red-700"],
                            ["High", summary.high, "text-orange-700"],
                            ["Medium", summary.medium, "text-yellow-700"],
                            ["Low", summary.low, "text-blue-700"],
                        ].map(([label, count, color]) => (
                            <div
                                key={label}
                                className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm"
                            >
                                <p className="text-sm text-gray-500">
                                    {label} Vulnerabilities
                                </p>
                                <p className={`mt-2 text-3xl font-bold ${color}`}>
                                    {count}
                                </p>
                            </div>
                        ))}
                    </section>

                    <RiskSummary
                        summary={summary}
                        riskScore={result.risk_score}
                        riskLevel={result.risk_level}
                    />

                    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                        <h2 className="mb-4 text-lg font-semibold">
                            Filter & Sort
                        </h2>

                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                            <label className="text-sm font-medium">
                                Severity
                                <select
                                    value={severityFilter}
                                    onChange={(event) =>
                                        setSeverityFilter(event.target.value)
                                    }
                                    className="mt-1 block w-full rounded-lg border p-2"
                                >
                                    {[
                                        "All",
                                        "Critical",
                                        "High",
                                        "Medium",
                                        "Low",
                                    ].map((item) => (
                                        <option key={item}>{item}</option>
                                    ))}
                                </select>
                            </label>

                            <label className="text-sm font-medium">
                                Vulnerability Type
                                <select
                                    value={typeFilter}
                                    onChange={(event) =>
                                        setTypeFilter(event.target.value)
                                    }
                                    className="mt-1 block w-full rounded-lg border p-2"
                                >
                                    <option value="All">All types</option>
                                    {vulnerabilityTypes.map((type) => (
                                        <option key={type} value={type}>
                                            {type}
                                        </option>
                                    ))}
                                </select>
                            </label>

                            <label className="text-sm font-medium">
                                Sort By
                                <select
                                    value={sortOrder}
                                    onChange={(event) =>
                                        setSortOrder(event.target.value)
                                    }
                                    className="mt-1 block w-full rounded-lg border p-2"
                                >
                                    <option value="severity-high">
                                        Highest severity first
                                    </option>
                                    <option value="severity-low">
                                        Lowest severity first
                                    </option>
                                    <option value="risk-high">
                                        Highest risk first
                                    </option>
                                    <option value="risk-low">
                                        Lowest risk first
                                    </option>
                                    <option value="file-az">File name A-Z</option>
                                    <option value="file-za">File name Z-A</option>
                                    <option value="line-low">
                                        Line number low to high
                                    </option>
                                    <option value="line-high">
                                        Line number high to low
                                    </option>
                                </select>
                            </label>

                            <div className="flex items-end">
                                <button
                                    type="button"
                                    onClick={handleResetFilters}
                                    className="w-full rounded-lg border border-gray-300 px-4 py-2"
                                >
                                    Reset Filters
                                </button>
                            </div>
                        </div>
                    </section>

                    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                            <h2 className="text-lg font-semibold">
                                Detected Vulnerabilities
                            </h2>
                            <p className="text-sm text-gray-600">
                                Showing {sortedVulnerabilities.length} of{" "}
                                {vulnerabilities.length} findings
                            </p>
                        </div>

                        {sortedVulnerabilities.length === 0 ? (
                            <p className="rounded-lg bg-gray-50 p-4 text-gray-600">
                                No vulnerabilities match the selected filters.
                            </p>
                        ) : (
                            <div className="space-y-4">
                                {sortedVulnerabilities.map((item, index) => (
                                    <FindingCard
                                        key={
                                            item.id ??
                                            `${getVulnerabilityType(item)}-${item.file_name ?? item.filename ?? ""}-${item.line_number ?? ""}-${index}`
                                        }
                                        finding={item}
                                        onViewDetails={handleViewDetails}
                                    />
                                ))}
                            </div>
                        )}
                    </section>
                </>
            )}

            {!loading && !result && !error && (
                <section className="rounded-xl border border-gray-200 bg-white p-5">
                    <p>No scan result was found.</p>
                    <button
                        type="button"
                        onClick={() => navigate("/upload")}
                        className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-white"
                    >
                        Go to Upload
                    </button>
                </section>
            )}

            <footer className="flex flex-wrap gap-3">
                <button
                    type="button"
                    onClick={() => navigate("/upload")}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-white"
                >
                    Upload Another File
                </button>
                <button
                    type="button"
                    onClick={() => navigate("/projects")}
                    className="rounded-lg border border-gray-300 px-4 py-2"
                >
                    Back to Projects
                </button>
            </footer>
        </main>
    );
}

export default ScanResults;
