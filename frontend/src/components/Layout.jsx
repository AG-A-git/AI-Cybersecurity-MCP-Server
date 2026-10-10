
import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";

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

    return (
        <div
            style={{
                display: "flex",
                minHeight: "100vh",
                width: "100%",
                maxWidth: "100%",
                position: "relative",
            }}
        >
            <Sidebar
                mobileOpen={menuOpen}
                onNavigate={() => setMenuOpen(false)}
            />

            <div
                style={{
                    flex: 1,
                    minWidth: 0,
                }}
            >
                <Navbar onMenuClick={() => setMenuOpen(!menuOpen)} />

                <main
                    style={{
                        padding: "20px",
                        width: "100%",
                        boxSizing: "border-box",
                        overflowWrap: "anywhere",
                    }}
                >
                    {children}
                </main>
            </div>

            {menuOpen && (
                <button
                    type="button"
                    aria-label="Close navigation menu"
                    onClick={() => setMenuOpen(false)}
                    style={{
                        position: "fixed",
                        inset: 0,
                        zIndex: 9,
                        background: "rgba(0,0,0,0.35)",
                        border: "none",
                        width: "100%",
                        height: "100%",
                    }}
                />
            )}
        </div>
    );
}

export default Layout;
