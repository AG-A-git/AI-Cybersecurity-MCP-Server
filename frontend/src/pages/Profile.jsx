import { useEffect, useState } from "react";

import { getProfile } from "../services/profileService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";

function Profile() {
    const [profile, setProfile] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const fetchProfile = async () => {
        try {
            setLoading(true);
            setError("");

            const response = await getProfile();

            console.log("Profile:", response.data);

            setProfile(response.data);
        } catch (error) {
            console.error(
                "Failed to load profile:",
                error
            );

            setError(
                error.userMessage ||
                    error.response?.data?.detail ||
                    "Failed to load profile."
            );
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchProfile();
    }, []);

    if (loading) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Profile</h1>

                <LoadingState
                    message="Loading profile..."
                />
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "30px" }}>
                <h1>Profile</h1>

                <ErrorState
                    message={error}
                    onRetry={fetchProfile}
                />
            </div>
        );
    }

    return (
        <div style={{ padding: "30px" }}>
            <h1>Profile</h1>

            <hr />

            <div
                style={{
                    marginTop: "25px",
                    border: "1px solid #ccc",
                    borderRadius: "8px",
                    padding: "20px",
                    maxWidth: "600px",
                }}
            >
                {Object.entries(profile || {}).map(
                    ([key, value]) => (
                        <p key={key}>
                            <strong>
                                {key}:
                            </strong>{" "}
                            {String(value)}
                        </p>
                    )
                )}
            </div>

            <button
                type="button"
                onClick={fetchProfile}
                style={{
                    marginTop: "20px",
                }}
            >
                Refresh Profile
            </button>
        </div>
    );
}

export default Profile;