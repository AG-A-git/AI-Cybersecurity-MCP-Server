function EmptyState({
    title = "No data found",
    message = "There is nothing to display yet.",
    buttonText,
    onButtonClick,
}) {
    return (
        <div
            style={{
                padding: "40px",
                textAlign: "center",
                border: "1px solid #ddd",
                borderRadius: "8px",
                marginTop: "20px",
            }}
        >
            <h2>{title}</h2>

            <p>{message}</p>

            {buttonText && onButtonClick && (
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