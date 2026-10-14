import SeverityBadge from "./SeverityBadge";
import RiskBadge from "./RiskBadge";
import FindingMetadata from "./FindingMetadata";

function FindingCard({ finding, onViewDetails }) {
    const vulnerabilityType =
        finding.vulnerability_type ||
        finding.vulnerability ||
        finding.type ||
        "Unknown Vulnerability";

    const explanation =
        finding.explanation ||
        finding.description ||
        "No explanation available.";

    const riskScore = finding.risk_score;

    return (
        <article
            style={{
                border: "1px solid #ccc",
                borderRadius: "8px",
                padding: "20px",
                marginBottom: "15px",
                backgroundColor: "#fff",
            }}
        >
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "10px",
                    flexWrap: "wrap",
                }}
            >
                <h3 style={{ margin: 0 }}>
                    {vulnerabilityType}
                </h3>

                <div
                    style={{
                        display: "flex",
                        gap: "8px",
                        flexWrap: "wrap",
                    }}
                >
                    <SeverityBadge severity={finding.severity} />

                    {finding.risk_level && (
                        <RiskBadge riskLevel={finding.risk_level} />
                    )}
                </div>
            </div>

            <div style={{ marginTop: "15px" }}>
                <strong>Finding Risk Score:</strong>{" "}
                {riskScore !== null &&
                riskScore !== undefined &&
                riskScore !== ""
                    ? `${riskScore}/100`
                    : "Not available"}
            </div>

            <FindingMetadata finding={finding} />

            <section style={{ marginTop: "15px" }}>
                <h4>Explanation</h4>
                <p>{explanation}</p>
            </section>

            {finding.recommendation && (
                <section style={{ marginTop: "12px" }}>
                    <h4>Recommendation</h4>
                    <p>{finding.recommendation}</p>
                </section>
            )}

            {onViewDetails && (
                <button
                    type="button"
                    onClick={() => onViewDetails(finding)}
                    style={{
                        marginTop: "12px",
                        padding: "8px 14px",
                        borderRadius: "6px",
                        border: "1px solid #ccc",
                        cursor: "pointer",
                    }}
                >
                    View Details
                </button>
            )}
        </article>
    );
}

export default FindingCard;