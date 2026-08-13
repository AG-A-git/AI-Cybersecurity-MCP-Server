import { Link, useNavigate } from "react-router-dom";

function Dashboard() {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem("access_token");
        navigate("/login");
    };

    return (
        <div>
            <h1>Dashboard</h1>

            <p>Welcome to the AI Cybersecurity Dashboard.</p>

            <nav>
                <ul>
                    <li>
                        <Link to="/dashboard">
                            Dashboard
                        </Link>
                    </li>

                    <li>
                        <Link to="/projects">
                            Projects
                        </Link>
                    </li>

                    <li>
                        <Link to="/history">
                            History
                        </Link>
                    </li>

                    <li>
                        <Link to="/reports">
                            Reports
                        </Link>
                    </li>

                    <li>
                        <Link to="/profile">
                            Profile
                        </Link>
                    </li>

                    <li>
                        <button onClick={handleLogout}>
                            Logout
                        </button>
                    </li>
                </ul>
            </nav>

            <hr />

            <h2>Security Dashboard</h2>

            <p>
                Your cybersecurity projects and scan results
                will appear here.
            </p>
        </div>
    );
}

export default Dashboard;