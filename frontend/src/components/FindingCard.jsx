import SeverityBadge from "./SeverityBadge";
import RiskBadge from "./RiskBadge";
import FindingMetadata from "./FindingMetadata";

function FindingCard({ finding, onViewDetails }) {
    return (
        <div
            style={{
                border: "1px solid #ccc",
                borderRadius: "8px",
                padding: "20px",
                marginBottom: "15px",
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
                    {finding.vulnerability_type ||
                        "Unknown Vulnerability"}
                </h3>

                <div
                    style={{
                        display: "flex",
                        gap: "8px",
                        flexWrap: "wrap",
                    }}
                >
                    <SeverityBadge
                        severity={finding.severity}
                    />

                    <RiskBadge
                        riskLevel={finding.risk_level}
                    />
                </div>
            </div>

            <div style={{ marginTop: "15px" }}>
                <strong>Risk Score:</strong>{" "}
                {finding.risk_score ?? "Not available"}
            </div>

            <FindingMetadata finding={finding} />

            <div style={{ marginTop: "15px" }}>
                <strong>Explanation</strong>

                <p>
                    {finding.explanation ||
                        "No explanation available."}
                </p>
            </div>

            {onViewDetails && (
                <button
                    type="button"
                    onClick={() => onViewDetails(finding)}
                >
                    View Details
                </button>
            )}
        </div>
    );
}

export default FindingCard;