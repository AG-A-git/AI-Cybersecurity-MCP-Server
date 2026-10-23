import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { loginUser } from "../services/authService";
import "../styles/Login.css";

function Login() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();

        setError("");
        setLoading(true);

        try {
            const response = await loginUser({
                email,
                password,
            });

            const accessToken = response.data.access_token;

            if (!accessToken) {
                throw new Error("No access token received from server.");
            }

            localStorage.setItem("access_token", accessToken);
            navigate("/dashboard");
        } catch (error) {
            console.error("Login error:", error);

            if (error.userMessage) {
                setError(error.userMessage);
            } else if (error.response?.data?.detail) {
                setError(error.response.data.detail);
            } else if (error.message) {
                setError(error.message);
            } else {
                setError(
                    "Login failed. Please check your email and password."
                );
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="login-page">
            <section className="login-card">
                <h1 className="login-title">Login</h1>

                <form className="login-form" onSubmit={handleSubmit}>
                    <div className="login-field">
                        <label htmlFor="email">Email</label>
                        <input
                            id="email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="Enter your email"
                            autoComplete="email"
                            required
                        />
                    </div>

                    <div className="login-field">
                        <label htmlFor="password">Password</label>
                        <input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter your password"
                            autoComplete="current-password"
                            required
                        />
                    </div>

                    {error && (
                        <p className="login-error" role="alert">
                            {error}
                        </p>
                    )}

                    <button
                        className="login-button"
                        type="submit"
                        disabled={loading}
                    >
                        {loading ? "Logging in..." : "Login"}
                    </button>
                </form>

                <p className="login-register">
                    Don't have an account?{" "}
                    <Link to="/register">Register</Link>
                </p>
            </section>
        </main>
    );
}

export default Login;
