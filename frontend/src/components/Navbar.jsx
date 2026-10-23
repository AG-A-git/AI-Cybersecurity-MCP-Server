import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/Navbar.css";

function Navbar({ onMenuClick, menuOpen = false }) {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("selected_project_id");
        navigate("/login");
    };

    return (
        <nav aria-label="Top navigation" className="app-navbar">
            <div className="app-navbar__brand">
                <button
                    type="button"
                    onClick={onMenuClick}
                    aria-label={
                        menuOpen
                            ? "Close navigation menu"
                            : "Open navigation menu"
                    }
                    aria-expanded={menuOpen}
                    aria-controls="app-sidebar"
                    className="app-navbar__button app-navbar__menu-button"
                >
                    <span aria-hidden="true">☰</span>
                </button>

                <h2 className="app-navbar__title">
                    AI Cybersecurity MCP
                </h2>
            </div>

            <button
                type="button"
                onClick={handleLogout}
                className="app-navbar__button app-navbar__logout"
            >
                Logout
            </button>
        </nav>
    );
}

export default Navbar;
