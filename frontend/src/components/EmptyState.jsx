function EmptyState({
    title = "No data found",
    message = "",
    buttonText = "",
    onButtonClick,
}) {
    return (
        <div
            style={{
                padding: "30px",
                textAlign: "center",
                border: "1px solid #ddd",
                borderRadius: "8px",
            }}
        >
            <h3>{title}</h3>

            {message && <p>{message}</p>}

            {buttonText && (
                <button
                    type="button"
                    onClick={onButtonClick}
                >
                    {buttonText}
                </button>
            )}
        </div>
    );
}

export default EmptyState;