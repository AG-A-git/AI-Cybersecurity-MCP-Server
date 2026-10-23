import React from "react";
import { Link, useLocation } from "react-router-dom";
import "../styles/Sidebar.css";

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
        <aside
            id="app-sidebar"
            className={`app-sidebar ${
                mobileOpen ? "mobile-open" : ""
            }`}
        >
            <h3 className="app-sidebar__heading">Menu</h3>

            <nav
                aria-label="Main navigation"
                className="app-sidebar__nav"
            >
                {menuItems.map((item) => {
                    const isActive = location.pathname === item.path;

                    return (
                        <Link
                            key={item.path}
                            to={item.path}
                            onClick={onNavigate}
                            aria-current={isActive ? "page" : undefined}
                            className="app-sidebar-link"
                        >
                            {item.name}
                        </Link>
                    );
                })}
            </nav>
        </aside>
    );
}

export default Sidebar;
