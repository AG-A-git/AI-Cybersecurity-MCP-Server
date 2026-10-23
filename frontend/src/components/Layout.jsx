import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";
import "../styles/Layout.css";

function Layout({ children }) {
    const [menuOpen, setMenuOpen] = useState(false);

    useEffect(() => {
        const closeMenu = () => {
            if (window.innerWidth > 600) {
                setMenuOpen(false);
            }
        };

        window.addEventListener("resize", closeMenu);

        return () => {
            window.removeEventListener("resize", closeMenu);
        };
    }, []);

    useEffect(() => {
        if (!menuOpen) return;

        const handleEscape = (event) => {
            if (event.key === "Escape") {
                setMenuOpen(false);
            }
        };

        window.addEventListener("keydown", handleEscape);

        return () => {
            window.removeEventListener("keydown", handleEscape);
        };
    }, [menuOpen]);

    const closeMenu = () => setMenuOpen(false);

    return (
        <div className="app-shell">
            <Sidebar
                mobileOpen={menuOpen}
                onNavigate={closeMenu}
            />

            <div className="app-shell__content">
                <Navbar
                    menuOpen={menuOpen}
                    onMenuClick={() => setMenuOpen((open) => !open)}
                />

                <main
                    id="main-content"
                    tabIndex={-1}
                    className="app-shell__main"
                >
                    {children}
                </main>
            </div>

            {menuOpen && (
                <button
                    type="button"
                    aria-label="Close navigation menu"
                    onClick={closeMenu}
                    className="app-shell__backdrop"
                />
            )}
        </div>
    );
}

export default Layout;
