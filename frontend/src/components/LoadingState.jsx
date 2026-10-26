
import "../styles/StateComponents.css";

function LoadingState({ message = "Loading..." }) {
    return (
        <div className="state-container state-loading">
            <div
                className="state-spinner"
                aria-hidden="true"
            />
            <p role="status" aria-live="polite">
                {message}
            </p>
        </div>
    );
}

export default LoadingState;
