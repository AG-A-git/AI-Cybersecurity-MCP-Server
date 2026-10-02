function ScanStatus({ status }) {
    const normalizedStatus = String(status || "")
        .trim()
        .toLowerCase();

    let label = "Unknown";
    let message = "Scan status is not available.";

    switch (normalizedStatus) {
        case "pending":
            label = "Pending";
            message = "Scan is waiting to start.";
            break;

        case "running":
        case "in_progress":
            label = "Running";
            message = "Scan is currently running.";
            break;

        case "completed":
        case "complete":
            label = "Completed";
            message = "Scan completed successfully.";
            break;

        case "failed":
        case "error":
            label = "Failed";
            message = "Scan failed.";
            break;

        default:
            if (status) {
                label = status;
                message = `Current scan status: ${status}`;
            }
    }

    return (
        <div>
            <strong>{label}</strong>

            <div
                style={{
                    marginTop: "4px",
                    fontSize: "0.9rem",
                }}
            >
                {message}
            </div>
        </div>
    );
}

export default ScanStatus;