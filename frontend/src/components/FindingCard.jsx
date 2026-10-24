
import SeverityBadge from "./SeverityBadge";
import RiskBadge from "./RiskBadge";
import FindingMetadata from "./FindingMetadata";
import {
    getFindingGuidance,
    getAnalysisSource,
    getRemediation,
} from "../utils/findingGuidance";

function FindingCard({ finding, onViewDetails }) {
    const vulnerabilityType =
        finding.vulnerability_type ||
        finding.vulnerability ||
        finding.type ||
        "Unknown Vulnerability";

    const guidance = getFindingGuidance(finding);
    const remediation = getRemediation(finding);
    const analysisSource = getAnalysisSource(finding);

    const backendExplanation = String(
        finding.explanation ||
        finding.description ||
        ""
    ).trim();

    const genericExplanation =
        !backendExplanation ||
        backendExplanation ===
            "The scanner detected a potentially risky code pattern. Review the reported line and surrounding code to determine whether it is exploitable.";

    const explanation = genericExplanation
        ? guidance.explanation
        : backendExplanation;

    const recommendation = remediation.recommendation;

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

    const backendAnalysis = String(
        finding.ai_analysis ||
        finding.aiAnalysis ||
        ""
    ).trim();

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
                <small>
                    {genericExplanation
                        ? "Source: rule-based guidance"
                        : "Source: backend finding description"}
                </small>
            </section>

            {recommendation && (
                <section className="finding-card__section finding-card__recommendation">
                    <h4>Recommendation</h4>
                    <p>{recommendation}</p>
                    <small>
                        Source: {remediation.source === "backend"
                            ? "backend"
                            : "rule-based guidance"}
                    </small>
                </section>
            )}

            <section className="finding-card__section">
                <h4>Analysis</h4>

                {analysisSource.available && backendAnalysis ? (
                    <>
                        <p>{backendAnalysis}</p>
                        <small>{analysisSource.message}</small>
                    </>
                ) : (
                    <p>{analysisSource.message}</p>
                )}
            </section>

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