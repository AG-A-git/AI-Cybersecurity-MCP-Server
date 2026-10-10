
import React from "react";
import { Link, useLocation } from "react-router-dom";

const menuItems = [
    { name: "Dashboard", path: "/dashboard" },
    { name: "Upload", path: "/upload" },
    { name: "Results", path: "/scan-results" },
    { name: "History", path: "/history" },
    { name: "Reports", path: "/reports" },
];

function Sidebar({ mobileOpen = false, onNavigate = () => {} }) {
    const location = useLocation();

    return (
        <>
            <style>
                {`
                    .app-sidebar {
                        width: 180px;
                        min-width: 180px;
                        flex-shrink: 0;
                        min-height: 100vh;
                        box-sizing: border-box;
                        background: #1e293b;
                        color: white;
                        padding: 20px 12px;
                        z-index: 10;
                    }

                    @media (max-width: 600px) {
                        .app-sidebar {
                            position: fixed;
                            top: 0;
                            bottom: 0;
                            left: 0;
                            width: 240px;
                            min-width: 0;
                            min-height: 100vh;
                            overflow-y: auto;
                            transform: translateX(-100%);
                            transition: transform 0.25s ease;
                        }

                        .app-sidebar.mobile-open {
                            transform: translateX(0);
                        }
                    }
                `}
            </style>

            <aside
                className={`app-sidebar ${mobileOpen ? "mobile-open" : ""}`}
            >
                <h3 style={{ margin: "0 0 24px" }}>Menu</h3>

                <nav
                    aria-label="Main navigation"
                    style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "8px",
                    }}
                >
                    {menuItems.map((item) => {
                        const isActive =
                            location.pathname === item.path;

                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                onClick={onNavigate}
                                style={{
                                    display: "block",
                                    padding: "11px 12px",
                                    borderRadius: "6px",
                                    color: "white",
                                    backgroundColor: isActive
                                        ? "#2563eb"
                                        : "transparent",
                                    textDecoration: "none",
                                    fontSize: "15px",
                                }}
                            >
                                {item.name}
                            </Link>
                        );
                    })}
                </nav>
            </aside>
        </>
    );
}

export default Sidebar;
