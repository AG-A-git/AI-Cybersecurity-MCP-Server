function ErrorState({
    message = "Something went wrong.",
    onRetry,
}) {
    return (
        <div
            style={{
                padding: "30px",
                textAlign: "center",
                border: "1px solid #ddd",
                borderRadius: "8px",
                marginTop: "20px",
            }}
        >
            <h2>Unable to load data</h2>

            <p
                style={{
                    color: "red",
                }}
            >
                {message}
            </p>

            {onRetry && (
                <button
                    type="button"
                    onClick={onRetry}
                >
                    Try Again
                </button>
            )}
        </div>
    );
}

export default ErrorState;