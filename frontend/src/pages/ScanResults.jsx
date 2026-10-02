import { normalizeVulnerability } from "../utils/vulnerabilityUtils";
import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import RiskSummary from "../components/RiskSummary";
import FindingCard from "../components/FindingCard";

function ScanResults() {
    const location = useLocation();
    const navigate = useNavigate();

    // =====================================================
    // SCAN RESULT DATA
    // =====================================================

    const result = location.state?.result;
    const projectId = location.state?.projectId;

    // =====================================================
    // STATE
    // =====================================================

    const [severityFilter, setSeverityFilter] = useState("All");
    const [typeFilter, setTypeFilter] = useState("All");
    const [sortOrder, setSortOrder] = useState("severity-high");

    // =====================================================
    // NO RESULT
    // =====================================================

    if (!result) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Scan Results</h1>

                <p>No scan result found.</p>

                <button
                    type="button"
                    onClick={() => navigate("/upload")}
                >
                    Go to Upload
                </button>
            </div>
        );
    }

    // =====================================================
    // DATA FROM BACKEND
    // =====================================================

    const vulnerabilities = Array.isArray(result.vulnerabilities)
        ? result.vulnerabilities.map((item) =>
              normalizeVulnerability(item, result)
          )
        : [];

    const summary = result.summary || {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    // =====================================================
    // SEVERITY RANK
    // =====================================================

    const severityRank = {
        Critical: 4,
        High: 3,
        Medium: 2,
        Low: 1,
    };

    // =====================================================
    // GET VULNERABILITY TYPE
    // =====================================================

    const getVulnerabilityType = (item) => {
        return (
            item.vulnerability_type ||
            item.vulnerability ||
            item.type ||
            "Unknown"
        );
    };

    // =====================================================
    // UNIQUE VULNERABILITY TYPES
    // =====================================================

    const vulnerabilityTypes = [
        ...new Set(
            vulnerabilities.map((item) =>
                getVulnerabilityType(item)
            )
        ),
    ].sort();

    // =====================================================
    // FILTER BY SEVERITY
    // =====================================================

    const severityFiltered =
        severityFilter === "All"
            ? vulnerabilities
            : vulnerabilities.filter(
                  (item) =>
                      item.severity === severityFilter
              );

    // =====================================================
    // FILTER BY VULNERABILITY TYPE
    // =====================================================

    const filteredVulnerabilities =
        typeFilter === "All"
            ? severityFiltered
            : severityFiltered.filter(
                  (item) =>
                      getVulnerabilityType(item) ===
                      typeFilter
              );

    // =====================================================
    // SORT
    // =====================================================

    const sortedVulnerabilities = [
        ...filteredVulnerabilities,
    ].sort((a, b) => {
        // Severity high to low
        if (sortOrder === "severity-high") {
            const rankA =
                severityRank[a.severity] || 0;

            const rankB =
                severityRank[b.severity] || 0;

            return rankB - rankA;
        }

        // Severity low to high
        if (sortOrder === "severity-low") {
            const rankA =
                severityRank[a.severity] || 0;

            const rankB =
                severityRank[b.severity] || 0;

            return rankA - rankB;
        }

        // Risk high to low
        if (sortOrder === "risk-high") {
            const riskA =
                Number(a.risk_score) || 0;

            const riskB =
                Number(b.risk_score) || 0;

            return riskB - riskA;
        }

        // Risk low to high
        if (sortOrder === "risk-low") {
            const riskA =
                Number(a.risk_score) || 0;

            const riskB =
                Number(b.risk_score) || 0;

            return riskA - riskB;
        }

        // File name A-Z
        if (sortOrder === "file-az") {
            const fileA =
                a.file_name ||
                a.filename ||
                "";

            const fileB =
                b.file_name ||
                b.filename ||
                "";

            return fileA.localeCompare(fileB);
        }

        // File name Z-A
        if (sortOrder === "file-za") {
            const fileA =
                a.file_name ||
                a.filename ||
                "";

            const fileB =
                b.file_name ||
                b.filename ||
                "";

            return fileB.localeCompare(fileA);
        }

        // Line number low to high
        if (sortOrder === "line-low") {
            const lineA =
                Number(a.line_number) || 0;

            const lineB =
                Number(b.line_number) || 0;

            return lineA - lineB;
        }

        // Line number high to low
        if (sortOrder === "line-high") {
            const lineA =
                Number(a.line_number) || 0;

            const lineB =
                Number(b.line_number) || 0;

            return lineB - lineA;
        }

        return 0;
    });

    // =====================================================
    // VIEW DETAILS
    // =====================================================

    const handleViewDetails = (vulnerability) => {
        navigate("/vulnerability-details", {
            state: {
                vulnerability: vulnerability,
                projectId: projectId,
                fileName:
                    vulnerability.file_name ||
                    vulnerability.filename ||
                    result.filename,
            },
        });
    };

    // =====================================================
    // UPLOAD ANOTHER FILE
    // =====================================================

    const handleUploadAnother = () => {
        navigate("/upload");
    };

    // =====================================================
    // PROJECTS
    // =====================================================

    const handleBackToProjects = () => {
        navigate("/projects");
    };

    // =====================================================
    // RESET FILTERS
    // =====================================================

    const handleResetFilters = () => {
        setSeverityFilter("All");
        setTypeFilter("All");
        setSortOrder("severity-high");
    };

    return (
        <div
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            {/* HEADER */}

            <h1>Scan Results</h1>

            <p>
                Security analysis results for the uploaded
                source file.
            </p>

            <hr />

            {/* SCAN INFORMATION */}

            <section
                style={{
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                    marginTop: "20px",
                }}
            >
                <h2>Scan Information</h2>

                <p>
                    <strong>Project:</strong>{" "}
                    {result.project_name || "N/A"}
                </p>

                <p>
                    <strong>Project ID:</strong>{" "}
                    {projectId ||
                        result.project_id ||
                        "N/A"}
                </p>

                <p>
                    <strong>File:</strong>{" "}
                    {result.filename || "N/A"}
                </p>

                <p>
                    <strong>File Size:</strong>{" "}
                    {result.file_size !== undefined
                        ? `${result.file_size} bytes`
                        : "N/A"}
                </p>

                <p>
                    <strong>Uploaded By:</strong>{" "}
                    {result.uploaded_by || "N/A"}
                </p>

                <p>
                    <strong>Scan Status:</strong>{" "}
                    {result.message || "Completed"}
                </p>
            </section>

            {/* VULNERABILITY SUMMARY */}

            <section
                style={{
                    marginTop: "20px",
                }}
            >
                <h2>Vulnerability Summary</h2>

                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: "15px",
                    }}
                >
                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Total</h3>

                        <p
                            style={{
                                fontSize: "28px",
                                fontWeight: "bold",
                            }}
                        >
                            {result.total_vulnerabilities ??
                                vulnerabilities.length}
                        </p>
                    </div>

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Critical</h3>

                        <p
                            style={{
                                fontSize: "28px",
                                fontWeight: "bold",
                            }}
                        >
                            {summary.critical || 0}
                        </p>
                    </div>

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>High</h3>

                        <p
                            style={{
                                fontSize: "28px",
                                fontWeight: "bold",
                            }}
                        >
                            {summary.high || 0}
                        </p>
                    </div>

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Medium</h3>

                        <p
                            style={{
                                fontSize: "28px",
                                fontWeight: "bold",
                            }}
                        >
                            {summary.medium || 0}
                        </p>
                    </div>

                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "20px",
                        }}
                    >
                        <h3>Low</h3>

                        <p
                            style={{
                                fontSize: "28px",
                                fontWeight: "bold",
                            }}
                        >
                            {summary.low || 0}
                        </p>
                    </div>
                </div>
            </section>

            {/* RISK SUMMARY */}

            <RiskSummary
                summary={summary}
                riskScore={result.risk_score}
                riskLevel={result.risk_level}
            />

            {/* FILTER AND SORT */}

            <section
                style={{
                    marginTop: "30px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                }}
            >
                <h2>Filter & Sort</h2>

                <div
                    style={{
                        display: "flex",
                        gap: "20px",
                        flexWrap: "wrap",
                        alignItems: "center",
                    }}
                >
                    {/* SEVERITY FILTER */}

                    <div>
                        <label htmlFor="severityFilter">
                            <strong>
                                Severity:
                            </strong>
                        </label>

                        <select
                            id="severityFilter"
                            value={severityFilter}
                            onChange={(e) =>
                                setSeverityFilter(
                                    e.target.value
                                )
                            }
                            style={{
                                marginLeft: "10px",
                                padding: "6px",
                            }}
                        >
                            <option value="All">
                                All
                            </option>

                            <option value="Critical">
                                Critical
                            </option>

                            <option value="High">
                                High
                            </option>

                            <option value="Medium">
                                Medium
                            </option>

                            <option value="Low">
                                Low
                            </option>
                        </select>
                    </div>

                    {/* VULNERABILITY TYPE FILTER */}

                    <div>
                        <label htmlFor="typeFilter">
                            <strong>
                                Vulnerability Type:
                            </strong>
                        </label>

                        <select
                            id="typeFilter"
                            value={typeFilter}
                            onChange={(e) =>
                                setTypeFilter(
                                    e.target.value
                                )
                            }
                            style={{
                                marginLeft: "10px",
                                padding: "6px",
                            }}
                        >
                            <option value="All">
                                All
                            </option>

                            {vulnerabilityTypes.map(
                                (type) => (
                                    <option
                                        key={type}
                                        value={type}
                                    >
                                        {type}
                                    </option>
                                )
                            )}
                        </select>
                    </div>

                    {/* SORT */}

                    <div>
                        <label htmlFor="sortOrder">
                            <strong>
                                Sort:
                            </strong>
                        </label>

                        <select
                            id="sortOrder"
                            value={sortOrder}
                            onChange={(e) =>
                                setSortOrder(
                                    e.target.value
                                )
                            }
                            style={{
                                marginLeft: "10px",
                                padding: "6px",
                            }}
                        >
                            <option value="severity-high">
                                Highest Severity First
                            </option>

                            <option value="severity-low">
                                Lowest Severity First
                            </option>

                            <option value="risk-high">
                                Highest Risk First
                            </option>

                            <option value="risk-low">
                                Lowest Risk First
                            </option>

                            <option value="file-az">
                                File Name A-Z
                            </option>

                            <option value="file-za">
                                File Name Z-A
                            </option>

                            <option value="line-low">
                                Line Number Low to High
                            </option>

                            <option value="line-high">
                                Line Number High to Low
                            </option>
                        </select>
                    </div>

                    {/* RESET */}

                    <button
                        type="button"
                        onClick={handleResetFilters}
                    >
                        Reset Filters
                    </button>
                </div>
            </section>

            {/* VULNERABILITY LIST */}

            <section
                style={{
                    marginTop: "30px",
                }}
            >
                <h2>Detected Vulnerabilities</h2>

                <p>
                    Showing{" "}
                    <strong>
                        {sortedVulnerabilities.length}
                    </strong>{" "}
                    of{" "}
                    <strong>
                        {vulnerabilities.length}
                    </strong>{" "}
                    vulnerabilities.
                </p>

                {sortedVulnerabilities.length === 0 ? (
                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "25px",
                        }}
                    >
                        <h3>
                            No vulnerabilities found
                        </h3>

                        <p>
                            No vulnerabilities match
                            the selected filters.
                        </p>

                        <button
                            type="button"
                            onClick={handleResetFilters}
                        >
                            Reset Filters
                        </button>
                    </div>
                ) : (
                    <div>
                        {sortedVulnerabilities.map(
                            (item, index) => (
                                <FindingCard
                                    key={
                                        item.id ??
                                        `${getVulnerabilityType(
                                            item
                                        )}-${index}`
                                    }
                                    finding={item}
                                    onViewDetails={
                                        handleViewDetails
                                    }
                                />
                            )
                        )}
                    </div>
                )}
            </section>

            {/* ACTIONS */}

            <section
                style={{
                    marginTop: "30px",
                    display: "flex",
                    gap: "10px",
                    flexWrap: "wrap",
                }}
            >
                <button
                    type="button"
                    onClick={handleUploadAnother}
                >
                    Upload Another File
                </button>

                <button
                    type="button"
                    onClick={handleBackToProjects}
                >
                    Back to Projects
                </button>
            </section>
        </div>
    );
}

export default ScanResults;