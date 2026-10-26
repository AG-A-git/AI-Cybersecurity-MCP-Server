function FindingMetadata({ finding }) {
    const confidence = finding.confidence;

    const formattedConfidence =
        confidence === null ||
        confidence === undefined ||
        confidence === ""
            ? "Not available"
            : typeof confidence === "number" ||
              (typeof confidence === "string" &&
                  !Number.isNaN(Number(confidence)))
            ? `${confidence}%`
            : confidence;

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
                <p>{finding.file_name || finding.file || "Not available"}</p>
            </div>

            <div>
                <strong>Line</strong>
                <p>{finding.line_number ?? finding.line ?? "Not available"}</p>
            </div>

            <div>
                <strong>Confidence</strong>
                <p>{formattedConfidence}</p>
            </div>

            <div>
                <strong>OWASP</strong>
                <p>{finding.owasp || finding.owasp_category || "Not available"}</p>
            </div>

            <div>
                <strong>CWE</strong>
                <p>{finding.cwe || finding.cwe_id || "Not available"}</p>
            </div>

            <div>
                <strong>Scan Status</strong>
                <p>{finding.scan_status || "Not available"}</p>
            </div>
        </div>
    );
}

export default FindingMetadata;
