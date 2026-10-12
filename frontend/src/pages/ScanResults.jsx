
import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { getScanResults, getScans } from "../services/scanService";
import { normalizeVulnerability } from "../utils/vulnerabilityUtils";
import RiskSummary from "../components/RiskSummary";
import FindingCard from "../components/FindingCard";

function ScanResults() {
    const location = useLocation();
    const navigate = useNavigate();

    const initialResult = location.state?.result || null;
    const initialScanId =
        location.state?.scanId ??
        location.state?.scan_id ??
        initialResult?.id ??
        null;

    const [result, setResult] = useState(initialResult);
    const [scanId, setScanId] = useState(initialScanId);
    const [scanOptions, setScanOptions] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [severityFilter, setSeverityFilter] = useState("All");
    const [typeFilter, setTypeFilter] = useState("All");
    const [sortOrder, setSortOrder] = useState("severity-high");

    const projectId =
        location.state?.projectId ??
        result?.project_id ??
        null;

    const loadScanResults = useCallback(async (id) => {
        if (!id) return;

        setLoading(true);
        setError("");

        try {
            const response = await getScanResults(id);
            setResult(response.data);
            setScanId(response.data.id ?? id);
        } catch (err) {
            console.error("Failed to load scan results:", err);
            setError(
                err.response?.data?.detail ||
                err.userMessage ||
                "Could not load scan results. Please try again."
            );
        } finally {
            setLoading(false);
        }
    }, []);

    // Load a specific scan if the route supplied its ID.
    // Otherwise, fetch the scan list and select the latest one.
    useEffect(() => {
        let cancelled = false;

        async function initialize() {
            if (initialScanId) {
                await loadScanResults(initialScanId);
                return;
            }

            if (initialResult) {
                setResult(initialResult);
                return;
            }

            setLoading(true);
            setError("");

            try {
                const response = await getScans();
                const data = response.data;

                const scans = Array.isArray(data)
                    ? data
                    : Array.isArray(data?.scans)
                        ? data.scans
                        : [];

                if (cancelled) return;

                setScanOptions(scans);

                if (scans.length === 0) {
                    setError("No scans were found. Upload a file and start a scan first.");
                    setLoading(false);
                    return;
                }

                const latestScan = [...scans].sort(
                    (a, b) =>
                        new Date(b.created_at || 0).getTime() -
                        new Date(a.created_at || 0).getTime()
                )[0];

                setScanId(latestScan.id);
                await loadScanResults(latestScan.id);
            } catch (err) {
                if (!cancelled) {
                    console.error("Failed to load scans:", err);
                    setError(
                        err.response?.data?.detail ||
                        err.userMessage ||
                        "Could not load scans from the backend."
                    );
                    setLoading(false);
                }
            }
        }

        initialize();

        return () => {
            cancelled = true;
        };
    }, [initialScanId, initialResult, loadScanResults]);

    const vulnerabilities = useMemo(() => {
        if (!Array.isArray(result?.vulnerabilities)) return [];

        return result.vulnerabilities.map((item) =>
            normalizeVulnerability(item, result)
        );
    }, [result]);

    const summary = useMemo(() => {
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        vulnerabilities.forEach((item) => {
            const severity = String(item.severity || "").toLowerCase();

            if (severity === "critical") counts.critical++;
            else if (severity === "high") counts.high++;
            else if (severity === "medium") counts.medium++;
            else if (severity === "low") counts.low++;
        });

        return {
            ...counts,
            ...(result?.summary || {}),
        };
    }, [result, vulnerabilities]);

    const severityRank = {
        Critical: 4,
        High: 3,
        Medium: 2,
        Low: 1,
    };

    const getVulnerabilityType = (item) =>
        item.vulnerability_type ||
        item.vulnerability ||
        item.type ||
        "Unknown";

    const vulnerabilityTypes = useMemo(
        () =>
            [...new Set(vulnerabilities.map(getVulnerabilityType))].sort(),
        [vulnerabilities]
    );

    const sortedVulnerabilities = useMemo(() => {
        const filtered = vulnerabilities.filter((item) => {
            const severityMatches =
                severityFilter === "All" ||
                String(item.severity).toLowerCase() ===
                    severityFilter.toLowerCase();

            const typeMatches =
                typeFilter === "All" ||
                getVulnerabilityType(item) === typeFilter;

            return severityMatches && typeMatches;
        });

        return filtered.sort((a, b) => {
            const rankA = severityRank[a.severity] || 0;
            const rankB = severityRank[b.severity] || 0;

            switch (sortOrder) {
                case "severity-low":
                    return rankA - rankB;
                case "risk-high":
                    return (Number(b.risk_score) || 0) -
                        (Number(a.risk_score) || 0);
                case "risk-low":
                    return (Number(a.risk_score) || 0) -
                        (Number(b.risk_score) || 0);
                case "file-az":
                    return (a.file_name || a.filename || "").localeCompare(
                        b.file_name || b.filename || ""
                    );
                case "file-za":
                    return (b.file_name || b.filename || "").localeCompare(
                        a.file_name || a.filename || ""
                    );
                case "line-low":
                    return (Number(a.line_number) || 0) -
                        (Number(b.line_number) || 0);
                case "line-high":
                    return (Number(b.line_number) || 0) -
                        (Number(a.line_number) || 0);
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
                projectId: projectId ?? result?.project_id,
                scanId,
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

    return (
        <main
            style={{
                padding: "clamp(16px, 4vw, 30px)",
                maxWidth: "1200px",
                margin: "0 auto",
                overflowWrap: "anywhere",
            }}
        >
            <h1>Scan Results</h1>
            <p>Security analysis results from your backend scan.</p>

            {loading && <p role="status">Loading scan results...</p>}

            {error && (
                <div
                    role="alert"
                    style={{
                        padding: "12px",
                        margin: "16px 0",
                        borderRadius: "8px",
                        background: "#fef2f2",
                        color: "#991b1b",
                    }}
                >
                    {error}
                    <div style={{ marginTop: "10px" }}>
                        <button
                            type="button"
                            onClick={() => {
                                if (scanId) loadScanResults(scanId);
                                else window.location.reload();
                            }}
                        >
                            Retry
                        </button>
                    </div>
                </div>
            )}

            {!loading && result && (
                <>
                    <section
                        style={{
                            border: "1px solid #ddd",
                            borderRadius: "10px",
                            padding: "18px",
                            marginTop: "20px",
                        }}
                    >
                        <h2>Scan Information</h2>
                        <p><strong>Scan ID:</strong> {result.id ?? scanId ?? "N/A"}</p>
                        <p><strong>Project ID:</strong> {result.project_id ?? projectId ?? "N/A"}</p>
                        <p><strong>Status:</strong> {result.status || result.message || "Completed"}</p>
                        <p>
                            <strong>Total vulnerabilities:</strong>{" "}
                            {result.vulnerability_count ?? vulnerabilities.length}
                        </p>
                        {result.created_at && (
                            <p>
                                <strong>Created:</strong>{" "}
                                {new Date(result.created_at).toLocaleString()}
                            </p>
                        )}
                    </section>

                    {scanOptions.length > 1 && (
                        <section style={{ marginTop: "20px" }}>
                            <label htmlFor="scan-select">
                                <strong>Select scan: </strong>
                            </label>
                            <select
                                id="scan-select"
                                value={scanId ?? ""}
                                onChange={(event) => {
                                    const id = event.target.value;
                                    setScanId(id);
                                    loadScanResults(id);
                                }}
                            >
                                {scanOptions.map((scan) => (
                                    <option key={scan.id} value={scan.id}>
                                        Scan #{scan.id} — {scan.status || "Unknown"}
                                    </option>
                                ))}
                            </select>
                        </section>
                    )}

                    <section style={{ marginTop: "24px" }}>
                        <h2>Vulnerability Summary</h2>
                        <div
                            style={{
                                display: "grid",
                                gridTemplateColumns:
                                    "repeat(auto-fit, minmax(130px, 1fr))",
                                gap: "12px",
                            }}
                        >
                            {[
                                ["Total", result.vulnerability_count ?? vulnerabilities.length],
                                ["Critical", summary.critical],
                                ["High", summary.high],
                                ["Medium", summary.medium],
                                ["Low", summary.low],
                            ].map(([label, value]) => (
                                <div
                                    key={label}
                                    style={{
                                        border: "1px solid #ddd",
                                        borderRadius: "8px",
                                        padding: "16px",
                                    }}
                                >
                                    <h3>{label}</h3>
                                    <p style={{ fontSize: "26px", fontWeight: "bold" }}>
                                        {value}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </section>

                    <RiskSummary
                        summary={summary}
                        riskScore={result.risk_score}
                        riskLevel={result.risk_level}
                    />

                    <section
                        style={{
                            marginTop: "28px",
                            border: "1px solid #ddd",
                            borderRadius: "10px",
                            padding: "18px",
                        }}
                    >
                        <h2>Filter & Sort</h2>

                        <div
                            style={{
                                display: "flex",
                                flexWrap: "wrap",
                                gap: "16px",
                                alignItems: "center",
                            }}
                        >
                            <label>
                                Severity{" "}
                                <select
                                    value={severityFilter}
                                    onChange={(e) => setSeverityFilter(e.target.value)}
                                >
                                    {["All", "Critical", "High", "Medium", "Low"].map(
                                        (item) => (
                                            <option key={item}>{item}</option>
                                        )
                                    )}
                                </select>
                            </label>

                            <label>
                                Type{" "}
                                <select
                                    value={typeFilter}
                                    onChange={(e) => setTypeFilter(e.target.value)}
                                >
                                    <option value="All">All</option>
                                    {vulnerabilityTypes.map((type) => (
                                        <option key={type} value={type}>
                                            {type}
                                        </option>
                                    ))}
                                </select>
                            </label>

                            <label>
                                Sort{" "}
                                <select
                                    value={sortOrder}
                                    onChange={(e) => setSortOrder(e.target.value)}
                                >
                                    <option value="severity-high">Highest severity first</option>
                                    <option value="severity-low">Lowest severity first</option>
                                    <option value="risk-high">Highest risk first</option>
                                    <option value="risk-low">Lowest risk first</option>
                                    <option value="file-az">File name A-Z</option>
                                    <option value="file-za">File name Z-A</option>
                                    <option value="line-low">Line number low to high</option>
                                    <option value="line-high">Line number high to low</option>
                                </select>
                            </label>

                            <button type="button" onClick={handleResetFilters}>
                                Reset Filters
                            </button>
                        </div>
                    </section>

                    <section style={{ marginTop: "28px" }}>
                        <h2>Detected Vulnerabilities</h2>
                        <p>
                            Showing {sortedVulnerabilities.length} of{" "}
                            {vulnerabilities.length} findings.
                        </p>

                        {sortedVulnerabilities.length === 0 ? (
                            <p>No vulnerabilities match the selected filters.</p>
                        ) : (
                            sortedVulnerabilities.map((item, index) => (
                                <FindingCard
                                    key={item.id ?? `${getVulnerabilityType(item)}-${index}`}
                                    finding={item}
                                    onViewDetails={handleViewDetails}
                                />
                            ))
                        )}
                    </section>
                </>
            )}

            {!loading && !result && !error && (
                <section>
                    <p>No scan result found.</p>
                    <button type="button" onClick={() => navigate("/upload")}>
                        Go to Upload
                    </button>
                </section>
            )}

            <div
                style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: "10px",
                    marginTop: "28px",
                }}
            >
                <button type="button" onClick={() => navigate("/upload")}>
                    Upload Another File
                </button>
                <button type="button" onClick={() => navigate("/projects")}>
                    Back to Projects
                </button>
            </div>
        </main>
    );
}

export default ScanResults;
