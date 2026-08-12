import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { register } from "../services/api";

function Register() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  });

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    console.log("REGISTER BUTTON CLICKED");
    console.log("FORM DATA:", formData);

    setError("");
    setSuccess("");

    // Validation
    if (!formData.username.trim()) {
      setError("Username is required.");
      return;
    }

    if (!formData.email.trim()) {
      setError("Email is required.");
      return;
    }

    if (!formData.password) {
      setError("Password is required.");
      return;
    }

    if (formData.password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    try {
      setLoading(true);

      console.log("SENDING REGISTER REQUEST");

      // IMPORTANT:
      // api.js expects register(username, email, password)
      const response = await register(
        formData.username.trim(),
        formData.email.trim(),
        formData.password
      );

      console.log("REGISTER SUCCESS");
      console.log("REGISTER RESPONSE:", response);

      setSuccess(
        "Registration successful! Redirecting to login..."
      );

      setFormData({
        username: "",
        email: "",
        password: "",
      });

      setTimeout(() => {
        navigate("/login");
      }, 1500);

    } catch (error) {
      console.error("REGISTRATION ERROR:", error);

      if (error.response) {
        console.log(
          "SERVER RESPONSE:",
          error.response.data
        );

        console.log(
          "STATUS:",
          error.response.status
        );

        const detail = error.response.data?.detail;

        // FastAPI validation errors are usually an array
        if (Array.isArray(detail)) {
          const messages = detail
            .map((item) => item.msg)
            .filter(Boolean)
            .join(", ");

          setError(
            messages || "Invalid registration data."
          );
        } else if (typeof detail === "string") {
          setError(detail);
        } else {
          setError("Registration failed.");
        }

      } else if (error.request) {
        console.log(
          "REQUEST WAS SENT BUT NO RESPONSE WAS RECEIVED."
        );

        setError(
          "No response received from the server. Make sure the backend is running."
        );

      } else {
        console.log(
          "REQUEST SETUP ERROR:",
          error.message
        );

        setError(
          error.message ||
          "Registration failed."
        );
      }

    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">

      <div className="row justify-content-center">

        <div className="col-md-5">

          <div className="card shadow">

            <div className="card-body">

              <h2 className="text-center mb-4">
                Register
              </h2>

              {/* Error Message */}
              {error && (
                <div className="alert alert-danger">
                  {error}
                </div>
              )}

              {/* Success Message */}
              {success && (
                <div className="alert alert-success">
                  {success}
                </div>
              )}

              <form onSubmit={handleSubmit}>

                {/* Username */}
                <div className="mb-3">

                  <label
                    htmlFor="username"
                    className="form-label"
                  >
                    Username
                  </label>

                  <input
                    id="username"
                    type="text"
                    name="username"
                    className="form-control"
                    placeholder="Enter username"
                    value={formData.username}
                    onChange={handleChange}
                    disabled={loading}
                    required
                  />

                </div>

                {/* Email */}
                <div className="mb-3">

                  <label
                    htmlFor="email"
                    className="form-label"
                  >
                    Email
                  </label>

                  <input
                    id="email"
                    type="email"
                    name="email"
                    className="form-control"
                    placeholder="Enter email"
                    value={formData.email}
                    onChange={handleChange}
                    disabled={loading}
                    required
                  />

                </div>

                {/* Password */}
                <div className="mb-3">

                  <label
                    htmlFor="password"
                    className="form-label"
                  >
                    Password
                  </label>

                  <input
                    id="password"
                    type="password"
                    name="password"
                    className="form-control"
                    placeholder="Enter password"
                    value={formData.password}
                    onChange={handleChange}
                    disabled={loading}
                    required
                  />

                </div>

                {/* Register Button */}
                <button
                  type="submit"
                  className="btn btn-primary w-100"
                  disabled={loading}
                >
                  {loading
                    ? "Registering..."
                    : "Register"}
                </button>

              </form>

              {/* Login */}
              <div className="text-center mt-3">

                <span>
                  Already have an account?{" "}
                </span>

                <button
                  type="button"
                  className="btn btn-link p-0"
                  onClick={() =>
                    navigate("/login")
                  }
                >
                  Login
                </button>

              </div>

            </div>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Register;