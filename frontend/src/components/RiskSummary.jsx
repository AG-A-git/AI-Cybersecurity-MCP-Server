
function RiskSummary({ summary, riskScore, riskLevel }) {
    const safeSummary = summary || {};

    // Display the score returned by the backend without recalculating it.
    const score = Number(riskScore);

    const hasValidScore =
        riskScore !== null &&
        riskScore !== undefined &&
        riskScore !== "" &&
        Number.isFinite(score) &&
        score >= 0 &&
        score <= 100;

    const hasValidRiskLevel =
        typeof riskLevel === "string" && riskLevel.trim() !== "";

    const derivedLevel = !hasValidScore
        ? "Not available"
        : score >= 80
          ? "Critical"
          : score >= 60
            ? "High"
            : score >= 30
              ? "Medium"
              : score > 0
                ? "Low"
                : "Informational";

    const level = hasValidRiskLevel
        ? riskLevel.trim()
        : derivedLevel;
    const normalizedLevel = level.toLowerCase();

    const levelColor =
        normalizedLevel === "critical"
            ? "#b91c1c"
            : normalizedLevel === "high"
              ? "#c2410c"
              : normalizedLevel === "medium"
                ? "#a16207"
                : normalizedLevel === "low"
                  ? "#15803d"
                  : "#6b7280";

    const cards = [
        {
            label: "Critical",
            count: safeSummary.critical ?? 0,
            color: "#b91c1c",
        },
        {
            label: "High",
            count: safeSummary.high ?? 0,
            color: "#c2410c",
        },
        {
            label: "Medium",
            count: safeSummary.medium ?? 0,
            color: "#a16207",
        },
        {
            label: "Low",
            count: safeSummary.low ?? 0,
            color: "#15803d",
        },
    ];

    return (
        <section
            aria-labelledby="risk-summary-heading"
            style={{
                marginTop: "20px",
                border: "1px solid #e5e7eb",
                borderRadius: "12px",
                padding: "20px",
                backgroundColor: "#ffffff",
                boxShadow: "0 2px 8px rgba(0, 0, 0, 0.04)",
            }}
        >
            <h2
                id="risk-summary-heading"
                style={{
                    margin: "0 0 18px",
                    fontSize: "20px",
                    fontWeight: 700,
                    color: "#111827",
                }}
            >
                Risk Summary
            </h2>

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(150px, 1fr))",
                    gap: "14px",
                }}
            >
                {/* Overall risk score */}
                <div
                    style={{
                        padding: "16px",
                        borderRadius: "8px",
                        backgroundColor: "#f9fafb",
                        border: "1px solid #e5e7eb",
                    }}
                >
                    <p
                        style={{
                            margin: 0,
                            color: "#6b7280",
                            fontSize: "14px",
                        }}
                    >
                        Overall Risk Score
                    </p>

                    <p
                        style={{
                            margin: "8px 0 0",
                            fontSize: "26px",
                            fontWeight: 700,
                            color: "#111827",
                        }}
                    >
                        {hasValidScore ? `${score}/100` : "Not available"}
                    </p>

                    {hasValidScore && (
                        <>
                            <div
                                role="progressbar"
                                aria-label="Overall risk score"
                                aria-valuemin={0}
                                aria-valuemax={100}
                                aria-valuenow={score}
                                style={{
                                    height: "8px",
                                    marginTop: "12px",
                                    borderRadius: "10px",
                                    backgroundColor: "#e5e7eb",
                                    overflow: "hidden",
                                }}
                            >
                                <div
                                    style={{
                                        width: `${score}%`,
                                        height: "100%",
                                        backgroundColor: levelColor,
                                        borderRadius: "10px",
                                        transition: "width 0.3s ease",
                                    }}
                                />
                            </div>

                            <p
                                style={{
                                    margin: "6px 0 0",
                                    fontSize: "12px",
                                    color: "#6b7280",
                                }}
                            >
                                {score}% on a 0â€“100 scale
                            </p>
                        </>
                    )}
                </div>

                {/* Overall risk level */}
                <div
                    style={{
                        padding: "16px",
                        borderRadius: "8px",
                        backgroundColor: "#f9fafb",
                        border: "1px solid #e5e7eb",
                    }}
                >
                    <p
                        style={{
                            margin: 0,
                            color: "#6b7280",
                            fontSize: "14px",
                        }}
                    >
                        Overall Risk Level
                    </p>

                    <p
                        style={{
                            margin: "8px 0 0",
                            fontSize: "22px",
                            fontWeight: 700,
                            color: levelColor,
                            overflowWrap: "anywhere",
                        }}
                    >
                        {level}
                    </p>
                </div>

                {/* Vulnerability counts */}
                {cards.map((card) => (
                    <div
                        key={card.label}
                        style={{
                            padding: "16px",
                            borderRadius: "8px",
                            backgroundColor: "#ffffff",
                            border: "1px solid #e5e7eb",
                            borderLeft: `4px solid ${card.color}`,
                        }}
                    >
                        <p
                            style={{
                                margin: 0,
                                color: "#6b7280",
                                fontSize: "14px",
                            }}
                        >
                            {card.label} Vulnerabilities
                        </p>

                        <p
                            style={{
                                margin: "8px 0 0",
                                fontSize: "26px",
                                fontWeight: 700,
                                color: card.color,
                            }}
                        >
                            {card.count}
                        </p>
                    </div>
                ))}
            </div>
        </section>
    );
}

export default RiskSummary;
