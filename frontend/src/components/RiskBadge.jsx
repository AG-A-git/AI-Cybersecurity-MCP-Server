function RiskBadge({ riskLevel }) {
    const value = riskLevel || "Not available";

    return (
        <span
            style={{
                display: "inline-block",
                padding: "4px 10px",
                border: "1px solid #ccc",
                borderRadius: "12px",
                fontSize: "0.85rem",
                fontWeight: "bold",
            }}
        >
            {value}
        </span>
    );
}

export default RiskBadge;