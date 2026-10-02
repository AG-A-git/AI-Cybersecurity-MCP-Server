import React from "react";
import { useNavigate } from "react-router-dom";

function Navbar() {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        navigate("/login");
    };

    return (
        <nav
            style={{
                background: "#2563eb",
                color: "white",
                padding: "15px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
            }}
        >
            <h2>AI Cybersecurity MCP</h2>

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
                }}
            >
                Logout
            </button>
        </nav>
    );
}

export default Navbar;

