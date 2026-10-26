
import { Routes, Route, Navigate } from "react-router-dom";

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
            {/* Public routes */}
            <Route
                path="/login"
                element={<Login />}
            />

            <Route
                path="/register"
                element={<Register />}
            />

            {/* Protected dashboard */}
            <Route
                path="/dashboard"
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                }
            />

            {/* Protected projects */}
            <Route
                path="/projects"
                element={
                    <ProtectedRoute>
                        <Projects />
                    </ProtectedRoute>
                }
            />

            {/* Protected file upload and scan */}
            <Route
                path="/upload"
                element={
                    <ProtectedRoute>
                        <Upload />
                    </ProtectedRoute>
                }
            />

            {/* Scan results: support both route paths */}
            <Route
                path="/results"
                element={
                    <ProtectedRoute>
                        <ScanResults />
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

            {/* Vulnerability details */}
            <Route
                path="/vulnerability-details"
                element={
                    <ProtectedRoute>
                        <VulnerabilityDetails />
                    </ProtectedRoute>
                }
            />

            {/* Scan history */}
            <Route
                path="/history"
                element={
                    <ProtectedRoute>
                        <History />
                    </ProtectedRoute>
                }
            />

            {/* Reports */}
            <Route
                path="/reports"
                element={
                    <ProtectedRoute>
                        <Reports />
                    </ProtectedRoute>
                }
            />

            {/* User profile */}
            <Route
                path="/profile"
                element={
                    <ProtectedRoute>
                        <Profile />
                    </ProtectedRoute>
                }
            />

            {/* Default route */}
            <Route
                path="/"
                element={<Navigate to="/dashboard" replace />}
            />

            {/* Unknown routes */}
            <Route
                path="*"
                element={<Navigate to="/login" replace />}
            />
        </Routes>
    );
}

export default App;
