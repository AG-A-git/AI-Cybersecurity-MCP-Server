import React from "react";
import { Link } from "react-router-dom";

function Navbar() {
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

      <Link to="/login" style={{ color: "white", textDecoration: "none" }}>
        Logout
      </Link>
    </nav>
  );
}

export default Navbar;