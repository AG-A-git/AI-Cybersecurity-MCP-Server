import { Routes, Route } from "react-router-dom";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import Upload from "./pages/Upload";
import ScanResults from "./pages/ScanResults";
import VulnerabilityDetails from "./pages/VulnerabilityDetails";
import History from "./pages/History";
import Reports from "./pages/Reports";
import Profile from "./pages/Profile";

import ProtectedRoute from "./components/ProtectedRoute";

function App() {
    return (
        <Routes>

            {/* =========================
                PUBLIC ROUTES
            ========================= */}

            <Route
                path="/login"
                element={<Login />}
            />

            <Route
                path="/register"
                element={<Register />}
            />


            {/* =========================
                PROTECTED ROUTES
            ========================= */}

            <Route
                path="/dashboard"
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/projects"
                element={
                    <ProtectedRoute>
                        <Projects />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/upload"
                element={
                    <ProtectedRoute>
                        <Upload />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/scan-results"
                element={
                    <ProtectedRoute>
                        <ScanResults />
                    </ProtectedRoute>
                }
            />

            {/* Vulnerability Details */}
            <Route
                path="/vulnerability-details"
                element={
                    <ProtectedRoute>
                        <VulnerabilityDetails />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/history"
                element={
                    <ProtectedRoute>
                        <History />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/reports"
                element={
                    <ProtectedRoute>
                        <Reports />
                    </ProtectedRoute>
                }
            />

            <Route
                path="/profile"
                element={
                    <ProtectedRoute>
                        <Profile />
                    </ProtectedRoute>
                }
            />


            {/* =========================
                DEFAULT ROUTE
            ========================= */}

            <Route
                path="*"
                element={<Login />}
            />

        </Routes>
    );
}

export default App;