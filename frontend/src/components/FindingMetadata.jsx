function FindingMetadata({ finding }) {
    return (
        <div
            style={{
                display: "grid",
                gridTemplateColumns:
                    "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "12px",
                marginTop: "15px",
            }}
        >
            <div>
                <strong>File</strong>
                <p>{finding.file_name || "Not available"}</p>
            </div>

            <div>
                <strong>Line</strong>
                <p>{finding.line_number ?? "Not available"}</p>
            </div>

            <div>
                <strong>Confidence</strong>
                <p>
                    {finding.confidence !== null &&
                    finding.confidence !== undefined
                        ? `${finding.confidence}%`
                        : "Not available"}
                </p>
            </div>

            <div>
                <strong>OWASP</strong>
                <p>{finding.owasp || "Not available"}</p>
            </div>

            <div>
                <strong>CWE</strong>
                <p>{finding.cwe || "Not available"}</p>
            </div>

            <div>
                <strong>Status</strong>
                <p>{finding.status || "Not available"}</p>
            </div>
        </div>
    );
}

export default FindingMetadata;