
import React from "react";
import { useNavigate } from "react-router-dom";

function Navbar({ onMenuClick }) {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("selected_project_id");
        navigate("/login");
    };

    return (
        <nav
            style={{
                background: "#2563eb",
                color: "white",
                padding: "12px 16px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "12px",
                flexWrap: "wrap",
                boxSizing: "border-box",
                width: "100%",
            }}
        >
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    minWidth: 0,
                    flex: "1 1 auto",
                }}
            >
                <button
                    type="button"
                    onClick={onMenuClick}
                    aria-label="Open navigation menu"
                    style={{
                        display: "none",
                        background: "transparent",
                        border: "1px solid white",
                        color: "white",
                        padding: "8px 10px",
                        borderRadius: "5px",
                        cursor: "pointer",
                    }}
                    className="mobile-menu-button"
                >
                    ☰
                </button>

                <h2
                    style={{
                        margin: 0,
                        fontSize: "clamp(16px, 4vw, 24px)",
                        overflowWrap: "anywhere",
                    }}
                >
                    AI Cybersecurity MCP
                </h2>
            </div>

            <button
                type="button"
                onClick={handleLogout}
                style={{
                    background: "transparent",
                    border: "1px solid white",
                    color: "white",
                    padding: "8px 14px",
                    borderRadius: "5px",
                    cursor: "pointer",
                    flexShrink: 0,
                }}
            >
                Logout
            </button>

            <style>
                {`
                    @media (max-width: 600px) {
                        .mobile-menu-button {
                            display: inline-block !important;
                        }
                    }
                `}
            </style>
        </nav>
    );
}

export default Navbar;
