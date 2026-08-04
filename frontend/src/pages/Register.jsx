import React from "react";
import { Link } from "react-router-dom";

function Register() {
  return (
    <div>
      <h1>Register</h1>

      <form>
        <input
          type="text"
          placeholder="Enter your username"
        />

        <br />
        <br />

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

        <input
          type="password"
          placeholder="Confirm your password"
        />

        <br />
        <br />

        <button type="submit">
          Register
        </button>
      </form>

      <br />

      <p>
        Already have an account?{" "}
        <Link to="/login">
          Login
        </Link>
      </p>
    </div>
  );
}

export default Register;