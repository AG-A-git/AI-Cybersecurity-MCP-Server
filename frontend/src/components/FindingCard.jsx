
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

    const recommendation =
        finding.recommendation ||
        finding.remediation ||
        finding.ai_recommendation ||
        "";

    const riskScore = finding.risk_score;

    const hasRiskScore =
        riskScore !== null &&
        riskScore !== undefined &&
        riskScore !== "" &&
        Number.isFinite(Number(riskScore));

    const riskScoreLabel = hasRiskScore
        ? `${Number(riskScore)}/100`
        : "Not available";

    const findingId =
        finding.id ??
        finding.finding_id ??
        `${vulnerabilityType}-${finding.file || finding.file_name || "unknown"}-${finding.line || finding.line_number || "unknown"}`;

    return (
        <article
            className="finding-card"
            aria-labelledby={`finding-title-${findingId}`}
        >
            <div className="finding-card__header">
                <div className="finding-card__title-group">
                    <h3
                        id={`finding-title-${findingId}`}
                        className="finding-card__title"
                    >
                        {vulnerabilityType}
                    </h3>

                    <p className="finding-card__file">
                        {finding.file ||
                            finding.file_name ||
                            finding.filename ||
                            "File not available"}
                        {(finding.line ?? finding.line_number) != null && (
                            <> · Line {finding.line ?? finding.line_number}</>
                        )}
                    </p>
                </div>

                <div
                    className="finding-card__badges"
                    aria-label="Finding severity and risk"
                >
                    <SeverityBadge severity={finding.severity} />

                    {finding.risk_level && (
                        <RiskBadge riskLevel={finding.risk_level} />
                    )}
                </div>
            </div>

            <div className="finding-card__score">
                <span className="finding-card__score-label">
                    Finding risk score
                </span>
                <strong>{riskScoreLabel}</strong>
            </div>

            <div className="finding-card__metadata">
                <FindingMetadata finding={finding} />
            </div>

            <section className="finding-card__section">
                <h4>Explanation</h4>
                <p>{explanation}</p>
            </section>

            {recommendation && (
                <section className="finding-card__section finding-card__recommendation">
                    <h4>Recommendation</h4>
                    <p>{recommendation}</p>
                </section>
            )}

            {onViewDetails && (
                <div className="finding-card__actions">
                    <button
                        type="button"
                        className="finding-card__details-button"
                        onClick={() => onViewDetails(finding)}
                        aria-label={`View details for ${vulnerabilityType}`}
                    >
                        View Details
                    </button>
                </div>
            )}
        </article>
    );
}

export default FindingCard;
