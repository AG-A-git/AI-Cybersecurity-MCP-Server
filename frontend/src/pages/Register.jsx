import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { registerUser } from "../services/authService";
import "../styles/Register.css";

function Register() {
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (loading) return;

        setError("");
        setSuccess("");
        setLoading(true);

        try {
            await registerUser({
                username: username.trim(),
                email: email.trim(),
                password,
            });

            setSuccess("Your account was created successfully. Redirecting to sign in...");

            window.setTimeout(() => {
                navigate("/login", { replace: true });
            }, 1200);
        } catch (error) {
            console.error("Registration error:", error);

            if (error.userMessage) {
                setError(error.userMessage);
            } else if (error.response?.data?.detail) {
                const detail = error.response.data.detail;
                setError(
                    typeof detail === "string"
                        ? detail
                        : "Please check your details and try again."
                );
            } else {
                setError("Registration failed. Please try again.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="register-page">
            <section className="register-intro" aria-label="Application introduction">
                <Link className="register-brand" to="/login">
                    <span className="register-brand-mark" aria-hidden="true">⛨</span>
                    <span>AI Cybersecurity MCP</span>
                </Link>

                <p className="register-eyebrow">Security intelligence workspace</p>

                <h2 className="register-hero-title">
                    Start with security.
                    <br />
                    <span>Build with confidence.</span>
                </h2>

                <p className="register-hero-copy">
                    Create your account to organize projects, review code scan
                    findings, and access your security reports in one workspace.
                </p>
            </section>

            <section className="register-card" aria-labelledby="register-title">
                <header className="register-card-header">
                    <h1 className="register-title" id="register-title">
                        Create your account
                    </h1>
                    <p className="register-subtitle">
                        Enter your details to get started.
                    </p>
                </header>

                <form className="register-form" onSubmit={handleSubmit}>
                    <div className="register-field">
                        <label htmlFor="username">Username</label>
                        <input
                            id="username"
                            name="username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="Choose a username"
                            autoComplete="username"
                            minLength={3}
                            maxLength={50}
                            required
                            disabled={loading}
                        />
                    </div>

                    <div className="register-field">
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

                    <div className="register-field">
                        <label htmlFor="password">Password</label>
                        <div className="register-password-control">
                            <input
                                id="password"
                                name="password"
                                type={showPassword ? "text" : "password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Create a password"
                                autoComplete="new-password"
                                required
                                disabled={loading}
                            />
                            <button
                                className="register-password-toggle"
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
                        <p className="register-error" role="alert" aria-live="polite">
                            {error}
                        </p>
                    )}

                    {success && (
                        <p className="register-success" role="status" aria-live="polite">
                            {success}
                        </p>
                    )}

                    <button
                        className="register-button"
                        type="submit"
                        disabled={loading || Boolean(success)}
                    >
                        {loading ? "Creating account..." : "Create account"}
                    </button>
                </form>

                <p className="register-login">
                    Already have an account?{" "}
                    <Link to="/login">Sign in</Link>
                </p>

                <p className="register-security-note">
                    <span aria-hidden="true">●</span>
                    Your account gives you access to your security workspace.
                </p>
            </section>

            <p className="register-footer">
                AI Cybersecurity MCP · Security analysis workspace
            </p>
        </main>
    );
}

export default Register;
