import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { loginUser } from "../services/authService";
import "../styles/Login.css";

function Login() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (loading) return;

        setError("");
        setLoading(true);

        try {
            const response = await loginUser({
                email: email.trim(),
                password,
            });

            const accessToken = response.data?.access_token;

            if (!accessToken) {
                throw new Error("The server did not return an access token. Please try again.");
            }

            localStorage.setItem("access_token", accessToken);
            navigate("/dashboard", { replace: true });
        } catch (error) {
            console.error("Login error:", error);

            if (error.userMessage) {
                setError(error.userMessage);
            } else if (error.response?.data?.detail) {
                const detail = error.response.data.detail;
                setError(
                    typeof detail === "string"
                        ? detail
                        : "Please check your email and password."
                );
            } else if (error.message) {
                setError(error.message);
            } else {
                setError("Login failed. Please check your email and password.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="login-page">
            <section className="login-intro" aria-label="Application introduction">
                <div className="login-brand">
                    <span className="login-brand-mark" aria-hidden="true">
                        ⛨
                    </span>
                    <span>AI Cybersecurity MCP</span>
                </div>

                <p className="login-eyebrow">Security intelligence workspace</p>

                <h2 className="login-hero-title">
                    Secure your code.
                    <br />
                    <span>Strengthen your defense.</span>
                </h2>

                <p className="login-hero-copy">
                    Bring your security workflow into one workspace. Manage projects,
                    inspect scan findings, and review vulnerability analysis.
                </p>

                <ul className="login-feature-list">
                    <li>
                        <span className="login-feature-icon" aria-hidden="true">⌘</span>
                        Project-based security scanning
                    </li>
                    <li>
                        <span className="login-feature-icon" aria-hidden="true">⌕</span>
                        Clear vulnerability findings and evidence
                    </li>
                    <li>
                        <span className="login-feature-icon" aria-hidden="true">↗</span>
                        Scan history and report access
                    </li>
                </ul>
            </section>

            <section className="login-card" aria-labelledby="login-title">
                <header className="login-card-header">
                    <h1 className="login-title" id="login-title">
                        Welcome back
                    </h1>
                    <p className="login-subtitle">
                        Sign in to continue to your security workspace.
                    </p>
                </header>

                <form className="login-form" onSubmit={handleSubmit}>
                    <div className="login-field">
                        <label htmlFor="email">Email address</label>
                        <input
                            id="email"
                            name="email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="you@example.com"
                            autoComplete="email"
                            autoCapitalize="none"
                            spellCheck="false"
                            required
                            disabled={loading}
                        />
                    </div>

                    <div className="login-field">
                        <label htmlFor="password">Password</label>
                        <div className="login-password-control">
                            <input
                                id="password"
                                name="password"
                                type={showPassword ? "text" : "password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter your password"
                                autoComplete="current-password"
                                required
                                disabled={loading}
                            />
                            <button
                                className="login-password-toggle"
                                type="button"
                                onClick={() => setShowPassword((visible) => !visible)}
                                aria-label={showPassword ? "Hide password" : "Show password"}
                                aria-pressed={showPassword}
                                disabled={loading}
                            >
                                {showPassword ? "Hide" : "Show"}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <p className="login-error" role="alert" aria-live="polite">
                            {error}
                        </p>
                    )}

                    <button
                        className="login-button"
                        type="submit"
                        disabled={loading}
                    >
                        {loading ? "Signing in..." : "Sign in securely"}
                    </button>
                </form>

                <p className="login-register">
                    New to the workspace?{" "}
                    <Link to="/register">Create an account</Link>
                </p>

                <p className="login-security-note">
                    <span aria-hidden="true">●</span>
                    Use your registered account to sign in.
                </p>
            </section>

            <p className="login-footer">
                AI Cybersecurity MCP · Security analysis workspace
            </p>
        </main>
    );
}

export default Login;
