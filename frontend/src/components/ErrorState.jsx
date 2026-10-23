
import "../styles/StateComponents.css";

function ErrorState({
    message = "Something went wrong.",
    onRetry,
}) {
    return (
        <section
            className="state-container state-error"
            role="alert"
            aria-labelledby="state-error-title"
        >
            <h2 id="state-error-title">
                Unable to load data
            </h2>

            <p className="state-error__message">
                {message}
            </p>

            {onRetry && (
                <button
                    type="button"
                    className="state-button"
                    onClick={onRetry}
                >
                    Try Again
                </button>
            )}
        </section>
    );
}

export default ErrorState;
