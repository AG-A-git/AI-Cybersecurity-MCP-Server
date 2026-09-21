import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

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
    const [sortOrder, setSortOrder] = useState("high-to-low");

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

    const vulnerabilities = result.vulnerabilities || [];

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
    // FILTER
    // =====================================================

    const filteredVulnerabilities =
        severityFilter === "All"
            ? vulnerabilities
            : vulnerabilities.filter(
                  (item) =>
                      item.severity === severityFilter
              );

    // =====================================================
    // SORT
    // =====================================================

    const sortedVulnerabilities = [
        ...filteredVulnerabilities,
    ].sort((a, b) => {
        const rankA =
            severityRank[a.severity] || 0;

        const rankB =
            severityRank[b.severity] || 0;

        if (sortOrder === "high-to-low") {
            return rankB - rankA;
        }

        return rankA - rankB;
    });

    // =====================================================
    // VIEW DETAILS
    // =====================================================

    const handleViewDetails = (vulnerability) => {
        navigate("/vulnerability-details", {
            state: {
                vulnerability: vulnerability,
                projectId: projectId,
                fileName: result?.filename,
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

    return (
        <div
            style={{
                padding: "30px",
                maxWidth: "1200px",
                margin: "0 auto",
            }}
        >
            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <h1>Scan Results</h1>

            <p>
                Security analysis results for the uploaded source file.
            </p>

            <hr />

            {/* ================================================= */}
            {/* SCAN INFORMATION */}
            {/* ================================================= */}

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
                    {projectId || result.project_id || "N/A"}
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

            {/* ================================================= */}
            {/* SUMMARY */}
            {/* ================================================= */}

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
                    {/* TOTAL */}

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

                    {/* CRITICAL */}

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

                    {/* HIGH */}

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

                    {/* MEDIUM */}

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

                    {/* LOW */}

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

            {/* ================================================= */}
            {/* FILTER AND SORT */}
            {/* ================================================= */}

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
                    {/* FILTER */}

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
                            <option value="high-to-low">
                                Highest Severity First
                            </option>

                            <option value="low-to-high">
                                Lowest Severity First
                            </option>
                        </select>
                    </div>
                </div>
            </section>

            {/* ================================================= */}
            {/* VULNERABILITY LIST */}
            {/* ================================================= */}

            <section
                style={{
                    marginTop: "30px",
                }}
            >
                <h2>
                    Detected Vulnerabilities
                </h2>

                <p>
                    Showing{" "}
                    <strong>
                        {sortedVulnerabilities.length}
                    </strong>{" "}
                    vulnerability/vulnerabilities.
                </p>

                {sortedVulnerabilities.length === 0 ? (
                    <div
                        style={{
                            border: "1px solid #ccc",
                            borderRadius: "8px",
                            padding: "25px",
                        }}
                    >
                        <h3>No vulnerabilities found</h3>

                        <p>
                            No vulnerabilities match
                            the selected filter.
                        </p>
                    </div>
                ) : (
                    <div>
                        {sortedVulnerabilities.map(
                            (item, index) => (
                                <div
                                    key={`${item.vulnerability_type || item.vulnerability}-${index}`}
                                    style={{
                                        border: "1px solid #ccc",
                                        borderRadius: "8px",
                                        padding: "20px",
                                        marginBottom: "15px",
                                    }}
                                >
                                    {/* ================================================= */}
                                    {/* TITLE */}
                                    {/* ================================================= */}

                                    <h3>
                                        {item.vulnerability_type ||
                                            item.vulnerability ||
                                            "Unknown Vulnerability"}
                                    </h3>

                                    {/* ================================================= */}
                                    {/* BASIC INFORMATION */}
                                    {/* ================================================= */}

                                    <p>
                                        <strong>
                                            Severity:
                                        </strong>{" "}
                                        {item.severity ||
                                            "N/A"}
                                    </p>

                                    <p>
                                        <strong>
                                            Status:
                                        </strong>{" "}
                                        {item.status ||
                                            "Open"}
                                    </p>

                                    {/* ================================================= */}
                                    {/* RISK INFORMATION */}
                                    {/* ================================================= */}

                                    <p>
                                        <strong>
                                            Risk Score:
                                        </strong>{" "}
                                        {item.risk_score ??
                                            "N/A"}
                                    </p>

                                    <p>
                                        <strong>
                                            Confidence:
                                        </strong>{" "}
                                        {item.confidence !==
                                        undefined
                                            ? `${item.confidence}%`
                                            : "N/A"}
                                    </p>

                                    {/* ================================================= */}
                                    {/* OWASP / CWE */}
                                    {/* ================================================= */}

                                    <p>
                                        <strong>
                                            OWASP:
                                        </strong>{" "}
                                        {item.owasp ||
                                            "N/A"}
                                    </p>

                                    <p>
                                        <strong>
                                            CWE:
                                        </strong>{" "}
                                        {item.cwe ||
                                            "N/A"}
                                    </p>

                                    {/* ================================================= */}
                                    {/* DESCRIPTION */}
                                    {/* ================================================= */}

                                    <p>
                                        <strong>
                                            Description:
                                        </strong>{" "}
                                        {item.description ||
                                            item.explanation ||
                                            "No description available."}
                                    </p>

                                    {/* ================================================= */}
                                    {/* VIEW DETAILS */}
                                    {/* ================================================= */}

                                    <button
                                        type="button"
                                        onClick={() =>
                                            handleViewDetails(
                                                item
                                            )
                                        }
                                    >
                                        View Details
                                    </button>
                                </div>
                            )
                        )}
                    </div>
                )}
            </section>

            {/* ================================================= */}
            {/* ACTIONS */}
            {/* ================================================= */}

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