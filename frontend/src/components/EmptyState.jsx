
import "../styles/StateComponents.css";

function EmptyState({
    title = "No data found",
    message = "",
    buttonText = "",
    onButtonClick,
}) {
    return (
        <section className="state-container state-empty">
            <h3>{title}</h3>

            {message && <p>{message}</p>}

            {buttonText && onButtonClick && (
                <button
                    type="button"
                    className="state-button"
                    onClick={onButtonClick}
                >
                    {buttonText}
                </button>
            )}
        </section>
    );
}

export default EmptyState;
