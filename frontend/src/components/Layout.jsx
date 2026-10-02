
import React from "react";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";

function Layout({ children }) {
    return (
        <div
            style={{
                display: "flex",
                minHeight: "100vh",
            }}
        >
            <Sidebar />

            <div
                style={{
                    flex: 1,
                    minWidth: 0,
                }}
            >
                <Navbar />

                <div style={{ padding: "20px" }}>
                    {children}
                </div>
            </div>
        </div>
    );
}

export default Layout;
