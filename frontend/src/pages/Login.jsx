import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { login } from "../services/api";

function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");
    setLoading(true);

    const loginEmail = email.trim();

    console.log("================================");
    console.log("LOGIN BUTTON CLICKED");
    console.log("EMAIL SENT:", JSON.stringify(loginEmail));
    console.log("PASSWORD LENGTH:", password.length);
    console.log("================================");

    try {
      // Send email and password correctly
      const response = await login(loginEmail, password);

      console.log("LOGIN SUCCESS");
      console.log("BACKEND RESPONSE:", response);

      // Get JWT token from backend response
      const token = response.access_token;

      if (!token) {
        throw new Error("No access token received from server.");
      }

      // Save authentication token
      localStorage.setItem("token", token);

      console.log("TOKEN SAVED SUCCESSFULLY");

      setSuccess("Login successful! Redirecting...");

      setTimeout(() => {
        navigate("/");
      }, 500);

    } catch (error) {
      console.error("================================");
      console.error("LOGIN ERROR:", error);
      console.error("================================");

      if (error.response) {
        console.error(
          "SERVER STATUS:",
          error.response.status
        );

        console.error(
          "SERVER RESPONSE:",
          error.response.data
        );

        if (error.response.status === 401) {
          setError("Invalid email or password.");
        } else if (error.response.status === 422) {
          const detail = error.response.data?.detail;

          if (Array.isArray(detail)) {
            setError(
              detail
                .map((item) => item.msg)
                .join(", ")
            );
          } else {
            setError(
              detail ||
              "Invalid login data. Please check your email and password."
            );
          }
        } else {
          const detail = error.response.data?.detail;

          if (typeof detail === "string") {
            setError(detail);
          } else {
            setError("Login failed. Please try again.");
          }
        }

      } else if (error.request) {
        console.error(
          "REQUEST WAS SENT BUT NO RESPONSE WAS RECEIVED."
        );

        setError(
          "No response received from the server. Make sure the backend is running."
        );

      } else {
        console.error(
          "REQUEST ERROR:",
          error.message
        );

        setError(
          "Unable to login. Please try again."
        );
      }

    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f1f5f9",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        padding: "20px",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "400px",
          background: "#ffffff",
          padding: "30px",
          borderRadius: "10px",
          boxShadow: "0 4px 20px rgba(0, 0, 0, 0.1)",
        }}
      >
        <h1
          style={{
            textAlign: "center",
            marginBottom: "25px",
          }}
        >
          Login
        </h1>

        {/* Error message */}
        {error && (
          <div
            style={{
              background: "#fee2e2",
              color: "#b91c1c",
              padding: "12px",
              borderRadius: "6px",
              marginBottom: "20px",
            }}
          >
            {error}
          </div>
        )}

        {/* Success message */}
        {success && (
          <div
            style={{
              background: "#dcfce7",
              color: "#166534",
              padding: "12px",
              borderRadius: "6px",
              marginBottom: "20px",
            }}
          >
            {success}
          </div>
        )}

        <form onSubmit={handleSubmit}>

          {/* Email */}
          <div style={{ marginBottom: "20px" }}>
            <label
              htmlFor="email"
              style={{
                display: "block",
                marginBottom: "7px",
                fontWeight: "600",
              }}
            >
              Email
            </label>

            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              autoComplete="email"
              required
              style={{
                width: "100%",
                padding: "12px",
                border: "1px solid #cbd5e1",
                borderRadius: "6px",
                boxSizing: "border-box",
                fontSize: "15px",
              }}
            />
          </div>

          {/* Password */}
          <div style={{ marginBottom: "25px" }}>
            <label
              htmlFor="password"
              style={{
                display: "block",
                marginBottom: "7px",
                fontWeight: "600",
              }}
            >
              Password
            </label>

            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              autoComplete="current-password"
              required
              style={{
                width: "100%",
                padding: "12px",
                border: "1px solid #cbd5e1",
                borderRadius: "6px",
                boxSizing: "border-box",
                fontSize: "15px",
              }}
            />
          </div>

          {/* Login button */}
          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "12px",
              border: "none",
              borderRadius: "6px",
              background: loading
                ? "#94a3b8"
                : "#2563eb",
              color: "#ffffff",
              fontSize: "16px",
              fontWeight: "600",
              cursor: loading
                ? "not-allowed"
                : "pointer",
            }}
          >
            {loading ? "Logging in..." : "Login"}
          </button>

        </form>

        {/* Register */}
        <p
          style={{
            textAlign: "center",
            marginTop: "25px",
          }}
        >
          Don't have an account?{" "}

          <Link
            to="/register"
            style={{
              color: "#2563eb",
              textDecoration: "none",
              fontWeight: "600",
            }}
          >
            Register
          </Link>
        </p>

      </div>
    </div>
  );
}

export default Login;