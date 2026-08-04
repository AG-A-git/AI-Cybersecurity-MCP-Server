import React from "react";
import { Link } from "react-router-dom";

function Login() {
  return (
    <div>
      <h1>Login</h1>

      <form>
        <input
          type="email"
          placeholder="Enter your email"
        />

        <br />
        <br />

        <input
          type="password"
          placeholder="Enter your password"
        />

        <br />
        <br />

        <button type="submit">
          Login
        </button>
      </form>

      <br />

      <p>
        Don't have an account?{" "}
        <Link to="/register">
          Register
        </Link>
      </p>
    </div>
  );
}

export default Login;