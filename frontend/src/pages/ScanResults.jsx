
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { getScanResults } from "../services/scanService";
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
    item.vulnerability_type ||
    item.vulnerability ||
    item.type ||
    item.name ||
    "Unknown";

const getValidScanId = (value) => {
    if (
        value === null ||
        value === undefined ||
        String(value).trim() === "" ||
        !Number.isInteger(Number(value)) ||
        Number(value) <= 0
    ) {
        return null;
    }

    return Number(value);
};

function ScanResults() {
    const location = useLocation();
    const navigate = useNavigate();
    const { scanId: routeScanId } = useParams();

    const initialState = useMemo(() => {
        const navigationResult = location.state?.result;
        const navigationScanId = getValidScanId(
            location.state?.scanId ??
                navigationResult?.scan_id ??
                navigationResult?.id
        );

        if (
            navigationResult &&
            navigationScanId &&
            getValidScanId(
                navigationResult.scan_id ?? navigationResult.id
            ) === navigationScanId
        ) {
            return {
                scanId: navigationScanId,
                result: navigationResult,
            };
        }

        try {
            const saved = sessionStorage.getItem(STORAGE_KEY);

            if (saved) {
                const parsed = JSON.parse(saved);
                const savedScanId = getValidScanId(parsed?.scanId);
                const savedResultId = getValidScanId(
                    parsed?.result?.scan_id ?? parsed?.result?.id
                );

                if (
                    savedScanId &&
                    savedResultId === savedScanId
                ) {
                    return {
                        scanId: savedScanId,
                        result: parsed.result,
                    };
                }
            }
        } catch (err) {
            console.warn("Could not restore saved scan results:", err);
        }

        return { scanId: null, result: null };
    }, [location.state]);

    const requestedScanId = getValidScanId(routeScanId);
    const scanId = requestedScanId ?? initialState.scanId;

    const [result, setResult] = useState(() => {
        if (!initialState.result) return null;

        const initialResultId = getValidScanId(
            initialState.result.scan_id ?? initialState.result.id
        );

        return initialResultId === scanId ? initialState.result : null;
    });

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [searchTerm, setSearchTerm] = useState("");
    const [severityFilter, setSeverityFilter] = useState("All");
    const [typeFilter, setTypeFilter] = useState("All");
    const [sortOrder, setSortOrder] = useState("severity-high");

    const resultRef = useRef(result);
    const requestNumber = useRef(0);

    useEffect(() => {
        resultRef.current = result;
    }, [result]);

    const loadScanResults = useCallback(async () => {
        const validScanId = getValidScanId(scanId);

        if (!validScanId) {
            resultRef.current = null;
            setResult(null);
            setLoading(false);
            setError(
                "No valid scan ID was found. Return to Upload and start a scan."
            );
            return;
        }

        const currentRequest = ++requestNumber.current;

        // Only retain existing data if it belongs to the requested scan.
        const currentResultId = getValidScanId(
            resultRef.current?.scan_id ?? resultRef.current?.id
        );

        if (currentResultId !== validScanId) {
            resultRef.current = null;
            setResult(null);
        }

        setLoading(true);
        setError("");

        try {
            const data = await getScanResults(validScanId);

            if (currentRequest !== requestNumber.current) return;

            const returnedScanId = getValidScanId(
                data?.scan_id ?? data?.id
            );

            if (returnedScanId !== validScanId) {
                throw new Error(
                    "The backend returned results for a different scan."
                );
            }

            resultRef.current = data;
            setResult(data);

            sessionStorage.setItem(
                STORAGE_KEY,
                JSON.stringify({
                    scanId: validScanId,
                    result: data,
                })
            );
        } catch (err) {
            if (currentRequest !== requestNumber.current) return;

            console.error("Failed to load scan results:", err);

            // Clear findings rather than showing stale data as current.
            resultRef.current = null;
            setResult(null);

            setError(
                err.userMessage ||
                    err.response?.data?.detail ||
                    err.message ||
                    "Could not load scan results. Please try again."
            );
        } finally {
            if (currentRequest === requestNumber.current) {
                setLoading(false);
            }
        }
    }, [scanId]);

    useEffect(() => {
        const navigationResult = location.state?.result;
        const navigationScanId = getValidScanId(
            location.state?.scanId ??
                navigationResult?.scan_id ??
                navigationResult?.id
        );

        // Accept navigation data only when it matches the requested scan.
        if (
            navigationResult &&
            navigationScanId &&
            navigationScanId === getValidScanId(scanId) &&
            getValidScanId(
                navigationResult.scan_id ?? navigationResult.id
            ) === navigationScanId
        ) {
            resultRef.current = navigationResult;
            setResult(navigationResult);

            try {
                sessionStorage.setItem(
                    STORAGE_KEY,
                    JSON.stringify({
                        scanId: navigationScanId,
                        result: navigationResult,
                    })
                );
            } catch (err) {
                console.warn("Could not save scan results:", err);
            }
        } else {
            const currentResultId = getValidScanId(
                resultRef.current?.scan_id ?? resultRef.current?.id
            );

            if (currentResultId !== getValidScanId(scanId)) {
                resultRef.current = null;
                setResult(null);
            }
        }

        loadScanResults();

        return () => {
            requestNumber.current += 1;
        };
    }, [location.state, scanId, loadScanResults]);

    // Normalize findings and remove duplicates.
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

    // Search, filter, and sort findings.
    const sortedVulnerabilities = useMemo(() => {
        const query = searchTerm.trim().toLowerCase();

        const filtered = vulnerabilities.filter((item) => {
            const severityMatches =
                severityFilter === "All" ||
                String(item.severity ?? "").toLowerCase() ===
                    severityFilter.toLowerCase();

            const typeMatches =
                typeFilter === "All" ||
                getVulnerabilityType(item) === typeFilter;

            const searchableText = [
                getVulnerabilityType(item),
                item.file_name,
                item.filename,
                item.file,
                item.explanation,
                item.description,
                item.message,
                item.vulnerable_code,
                item.code,
                item.source_code,
                item.snippet,
                item.cwe,
                item.owasp,
                item.recommendation,
                item.remediation,
            ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            const searchMatches =
                !query || searchableText.includes(query);

            return severityMatches && typeMatches && searchMatches;
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
    }, [
        vulnerabilities,
        searchTerm,
        severityFilter,
        typeFilter,
        sortOrder,
    ]);

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
        setSearchTerm("");
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
                        disabled={loading}
                        className="mt-2 font-semibold underline disabled:opacity-50"
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
                            Search, Filter & Sort
                        </h2>

                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                            <label className="text-sm font-medium">
                                Search Findings
                                <input
                                    type="search"
                                    value={searchTerm}
                                    onChange={(event) =>
                                        setSearchTerm(event.target.value)
                                    }
                                    placeholder="Search type, file, CWE, code..."
                                    className="mt-1 block w-full rounded-lg border p-2"
                                />
                            </label>

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
                                        <option key={item} value={item}>
                                            {item}
                                        </option>
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
                        </div>

                        <button
                            type="button"
                            onClick={handleResetFilters}
                            className="mt-4 rounded-lg border border-gray-300 px-4 py-2"
                        >
                            Reset Search & Filters
                        </button>
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
                                No vulnerabilities match your search or filters.
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
