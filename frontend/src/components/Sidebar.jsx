

import React from "react";
import { Link, useLocation } from "react-router-dom";

const menuItems = [
    { name: "Dashboard", path: "/dashboard" },
    { name: "Upload", path: "/upload" },
    { name: "Results", path: "/scan-results" },
    { name: "History", path: "/history" },
    { name: "Reports", path: "/reports" },
];

function Sidebar({
    mobileOpen = false,
    onNavigate = () => {},
}) {
    const location = useLocation();

    return (
        <>
            <style>{`
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

                .app-sidebar-link {
                    display: block;
                    padding: 11px 12px;
                    border-radius: 6px;
                    color: white;
                    text-decoration: none;
                    font-size: 15px;
                    overflow-wrap: anywhere;
                }

                .app-sidebar-link:focus-visible {
                    outline: 3px solid #facc15;
                    outline-offset: 2px;
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

                @media (prefers-reduced-motion: reduce) {
                    .app-sidebar {
                        transition: none;
                    }
                }
            `}</style>

            <aside
                id="app-sidebar"
                className={`app-sidebar ${
                    mobileOpen ? "mobile-open" : ""
                }`}
            >
                <h3 style={{ margin: "0 0 24px" }}>
                    Menu
                </h3>

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
                                aria-current={
                                    isActive ? "page" : undefined
                                }
                                className="app-sidebar-link"
                                style={{
                                    backgroundColor: isActive
                                        ? "#2563eb"
                                        : "transparent",
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
