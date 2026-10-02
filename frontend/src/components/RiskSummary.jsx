function RiskSummary({ summary, riskScore, riskLevel }) {
    const safeSummary = summary || {};

    return (
        <section
            style={{
                marginTop: "20px",
                border: "1px solid #ccc",
                borderRadius: "8px",
                padding: "20px",
            }}
        >
            <h2>Risk Summary</h2>

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns:
                        "repeat(auto-fit, minmax(160px, 1fr))",
                    gap: "15px",
                }}
            >
                <div>
                    <strong>Risk Score</strong>
                    <p>
                        {riskScore ?? "Not available"}
                    </p>
                </div>

                <div>
                    <strong>Risk Level</strong>
                    <p>
                        {riskLevel ?? "Not available"}
                    </p>
                </div>

                <div>
                    <strong>Critical</strong>
                    <p>
                        {safeSummary.critical ?? 0}
                    </p>
                </div>

                <div>
                    <strong>High</strong>
                    <p>
                        {safeSummary.high ?? 0}
                    </p>
                </div>

                <div>
                    <strong>Medium</strong>
                    <p>
                        {safeSummary.medium ?? 0}
                    </p>
                </div>

                <div>
                    <strong>Low</strong>
                    <p>
                        {safeSummary.low ?? 0}
                    </p>
                </div>
            </div>
        </section>
    );
}

export default RiskSummary;