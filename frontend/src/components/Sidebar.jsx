import React from "react";
import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <div
      style={{
        width: "220px",
        background: "#1e293b",
        color: "white",
        minHeight: "100vh",
        padding: "20px",
      }}
    >
      <h3>Menu</h3>

      <p><Link to="/" style={{ color: "white" }}>Dashboard</Link></p>
      <p><Link to="/upload" style={{ color: "white" }}>Upload</Link></p>
      <p><Link to="/results" style={{ color: "white" }}>Results</Link></p>
      <p><Link to="/history" style={{ color: "white" }}>History</Link></p>
      <p><Link to="/reports" style={{ color: "white" }}>Reports</Link></p>
    </div>
  );
}

export default Sidebar;