function LoadingState({ message = "Loading..." }) {
    return (
        <div
            style={{
                padding: "40px",
                textAlign: "center",
            }}
        >
            <div
                style={{
                    width: "40px",
                    height: "40px",
                    border: "4px solid #ddd",
                    borderTop: "4px solid #333",
                    borderRadius: "50%",
                    margin: "0 auto 20px",
                    animation: "spin 1s linear infinite",
                }}
            />

            <p>{message}</p>

            <style>
                {`
                    @keyframes spin {
                        0% {
                            transform: rotate(0deg);
                        }

                        100% {
                            transform: rotate(360deg);
                        }
                    }
                `}
            </style>
        </div>
    );
}

export default LoadingState;