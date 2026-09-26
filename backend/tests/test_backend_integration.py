import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# --------------------------------------------------
# Add backend directory to Python path
# --------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# --------------------------------------------------
# Import application and database components
# --------------------------------------------------

from app import app
from database import Base, get_db


# --------------------------------------------------
# Test database
# --------------------------------------------------

TEST_DATABASE_URL = "sqlite:///./test_scanner.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine
)


# --------------------------------------------------
# Reset test database
# --------------------------------------------------

Base.metadata.drop_all(bind=test_engine)
Base.metadata.create_all(bind=test_engine)


# --------------------------------------------------
# Override FastAPI database dependency
# --------------------------------------------------

def override_get_db():
    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# --------------------------------------------------
# FastAPI test client
# --------------------------------------------------

client = TestClient(app)

def test_home_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["message"] == "Welcome to AI Cybersecurity MCP Server!"

def test_user_registration():
    response = client.post(
        "/register",
        json={
            "username": "integration_test_user",
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["username"] == "integration_test_user"
    assert data["email"] == "integration_test@example.com"

def test_user_login():
    response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["access_token"]

def test_authenticated_profile():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/profile",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email"] == "integration_test@example.com"

def test_profile_requires_authentication():
    response = client.get("/profile")

    assert response.status_code in (401, 403)

def test_project_creation():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.post(
        "/projects/",
        params={
            "project_name": "Integration Test Project",
            "description": "Project created during backend integration testing"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["data"]["project_name"] == "Integration Test Project"
    assert data["data"]["owner_id"]

def test_project_ownership_isolation():
    # ----------------------------------------------
    # Create second user
    # ----------------------------------------------
    register_response = client.post(
        "/register",
        json={
            "username": "second_test_user",
            "email": "second_test@example.com",
            "password": "SecondPassword123!"
        }
    )

    assert register_response.status_code == 200

    # ----------------------------------------------
    # Login as second user
    # ----------------------------------------------
    second_login = client.post(
        "/login",
        json={
            "email": "second_test@example.com",
            "password": "SecondPassword123!"
        }
    )

    assert second_login.status_code == 200

    second_token = second_login.json()["access_token"]

    # ----------------------------------------------
    # Create project as second user
    # ----------------------------------------------
    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Second User Project",
            "description": "Private project"
        },
        headers={
            "Authorization": f"Bearer {second_token}"
        }
    )

    assert project_response.status_code == 200

    project_id = project_response.json()["data"]["id"]

    # ----------------------------------------------
    # Login as first user
    # ----------------------------------------------
    first_login = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert first_login.status_code == 200

    first_token = first_login.json()["access_token"]

    # ----------------------------------------------
    # First user attempts unauthorized access
    # ----------------------------------------------
    response = client.get(
        f"/projects/{project_id}",
        headers={
            "Authorization": f"Bearer {first_token}"
        }
    )

    assert response.status_code == 403

def test_project_listing():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/projects/",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert isinstance(data["data"], list)

    project_names = [
        project["project_name"]
        for project in data["data"]
    ]

    assert "Integration Test Project" in project_names

def test_file_upload():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Upload Test Project",
            "description": "Project for upload integration testing"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert project_response.status_code == 200

    project_id = project_response.json()["data"]["id"]

    with open("tests/sample_upload.py", "rb") as test_file:
        response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "sample_upload.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["data"]["filename"] == "sample_upload.py"
    assert data["data"]["project_id"] == project_id

def test_upload_ownership_isolation():
    # Login as first user
    first_login = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert first_login.status_code == 200
    first_token = first_login.json()["access_token"]

    # Create project owned by first user
    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Private Upload Project",
            "description": "Ownership isolation test"
        },
        headers={
            "Authorization": f"Bearer {first_token}"
        }
    )

    assert project_response.status_code == 200
    project_id = project_response.json()["data"]["id"]

    # Login as second user
    second_login = client.post(
        "/login",
        json={
            "email": "second_test@example.com",
            "password": "SecondPassword123!"
        }
    )

    assert second_login.status_code == 200
    second_token = second_login.json()["access_token"]

    # Second user attempts to upload to first user's project
    with open("tests/sample_upload.py", "rb") as test_file:
        response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "unauthorized_upload.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {second_token}"
            }
        )

    assert response.status_code == 403

def test_scan_endpoint_integration(monkeypatch):
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Scan Integration Project",
            "description": "Project for scan integration testing"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert project_response.status_code == 200
    project_id = project_response.json()["data"]["id"]

    with open("tests/sample_upload.py", "rb") as test_file:
        upload_response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "sample_upload.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

    assert upload_response.status_code == 200

    # Replace the external AI dependency with a deterministic
    # integration-test response.
    def fake_ai_analysis(findings):
        results = []

        for finding in findings:
            results.append({
                **finding,
                "risk_score": 0,
                "owasp": None,
                "cwe": None,
                "explanation": None,
                "impact": None,
                "recommendation": None
            })

        return results

    monkeypatch.setattr(
        "services.scan_service.analyze_vulnerabilities",
        fake_ai_analysis
    )

    response = client.post(
        "/scans/",
        json={
            "project_id": project_id
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["data"]["scan_id"]
    assert data["data"]["project_id"] == project_id
    assert data["data"]["status"] == "completed"
    assert "results" in data["data"]

def test_scan_lifecycle():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Lifecycle Test Project",
            "description": "Scan lifecycle validation"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert project_response.status_code == 200
    project_id = project_response.json()["data"]["id"]

    with open("tests/sample_upload.py", "rb") as test_file:
        upload_response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "lifecycle_test.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

    assert upload_response.status_code == 200

    def fake_ai_analysis(findings):
        return [
            {
                **finding,
                "risk_score": 25,
                "owasp": None,
                "cwe": None,
                "explanation": "Test explanation",
                "impact": "Test impact",
                "recommendation": "Test recommendation"
            }
            for finding in findings
        ]

    monkeypatch = None

    # Import the service so we can temporarily replace its AI function.
    import services.scan_service as scan_service

    original_ai = scan_service.analyze_vulnerabilities
    scan_service.analyze_vulnerabilities = fake_ai_analysis

    try:
        scan_response = client.post(
            "/scans/",
            json={
                "project_id": project_id
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
    finally:
        scan_service.analyze_vulnerabilities = original_ai

    assert scan_response.status_code == 200

    scan_id = scan_response.json()["data"]["scan_id"]

    result_response = client.get(
        f"/scans/{scan_id}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert result_response.status_code == 200

    result = result_response.json()["data"]

    assert result["id"] == scan_id
    assert result["project_id"] == project_id
    assert result["status"] == "completed"
    assert result["started_at"] is not None
    assert result["completed_at"] is not None

def test_scan_results_and_risk_score():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Risk Test Project",
            "description": "Risk score integration test"
        },
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert project_response.status_code == 200
    project_id = project_response.json()["data"]["id"]

    with open("tests/sample_upload.py", "rb") as test_file:
        upload_response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "risk_test.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

    assert upload_response.status_code == 200

    import services.scan_service as scan_service

    def fake_scanner(file_path):
        return [
            {
                "file": "risk_test.py",
                "line": 1,
                "vulnerability": "SQL Injection",
                "severity": "High",
                "confidence": 95,
                "code": "query = 'SELECT * FROM users WHERE id=' + user_id"
            }
        ]

    def fake_ai_analysis(findings):
        return [
            {
                **finding,
                "risk_score": 75,
                "owasp": "A03:2021",
                "cwe": "CWE-89",
                "explanation": "Test vulnerability explanation",
                "impact": "Test security impact",
                "recommendation": "Use parameterized queries"
            }
            for finding in findings
        ]

    original_scanner = scan_service.run_scanner
    original_ai = scan_service.analyze_vulnerabilities

    scan_service.run_scanner = fake_scanner
    scan_service.analyze_vulnerabilities = fake_ai_analysis

    try:
        scan_response = client.post(
            "/scans/",
            json={
                "project_id": project_id
            },
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
    finally:
        scan_service.run_scanner = original_scanner
        scan_service.analyze_vulnerabilities = original_ai

    assert scan_response.status_code == 200

    scan_id = scan_response.json()["data"]["scan_id"]

    result_response = client.get(
        f"/scans/{scan_id}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert result_response.status_code == 200

    data = result_response.json()["data"]

    assert data["status"] == "completed"
    assert data["vulnerability_count"] == 1
    assert data["risk_score"] == 75

    vulnerability = data["vulnerabilities"][0]

    assert vulnerability["risk_score"] == 75
    assert vulnerability["owasp_category"] == "A03:2021"
    assert vulnerability["cwe_id"] == "CWE-89"
    assert vulnerability["explanation"] == "Test vulnerability explanation"
    assert vulnerability["recommendation"] == "Use parameterized queries"

def test_scan_history():
    login_response = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = client.get(
        "/scans/",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert isinstance(data["data"], list)

    assert len(data["data"]) >= 1

    scan = data["data"][0]

    assert "id" in scan
    assert "project_id" in scan
    assert "project_name" in scan
    assert "status" in scan
    assert "vulnerability_count" in scan
    assert "risk_score" in scan
    assert "created_at" in scan

def test_scan_result_ownership_isolation():
    # Login as first user
    first_login = client.post(
        "/login",
        json={
            "email": "integration_test@example.com",
            "password": "TestPassword123!"
        }
    )

    assert first_login.status_code == 200
    first_token = first_login.json()["access_token"]

    # Create project as first user
    project_response = client.post(
        "/projects/",
        params={
            "project_name": "Private Scan Project",
            "description": "Scan ownership isolation test"
        },
        headers={
            "Authorization": f"Bearer {first_token}"
        }
    )

    assert project_response.status_code == 200
    project_id = project_response.json()["data"]["id"]

    # Upload file
    with open("tests/sample_upload.py", "rb") as test_file:
        upload_response = client.post(
            "/upload/",
            params={
                "project_id": project_id
            },
            files={
                "file": (
                    "private_scan.py",
                    test_file,
                    "text/x-python"
                )
            },
            headers={
                "Authorization": f"Bearer {first_token}"
            }
        )

    assert upload_response.status_code == 200

    # Mock scanner + AI so this test is deterministic
    import services.scan_service as scan_service

    def fake_scanner(file_path):
        return [
            {
                "file": "private_scan.py",
                "line": 1,
                "vulnerability": "SQL Injection",
                "severity": "High",
                "confidence": 95,
                "code": "query = user_input"
            }
        ]

    def fake_ai_analysis(findings):
        return [
            {
                **finding,
                "risk_score": 80,
                "owasp": "A03:2021",
                "cwe": "CWE-89",
                "explanation": "Test explanation",
                "impact": "Test impact",
                "recommendation": "Use parameterized queries"
            }
            for finding in findings
        ]

    original_scanner = scan_service.run_scanner
    original_ai = scan_service.analyze_vulnerabilities

    scan_service.run_scanner = fake_scanner
    scan_service.analyze_vulnerabilities = fake_ai_analysis

    try:
        scan_response = client.post(
            "/scans/",
            json={
                "project_id": project_id
            },
            headers={
                "Authorization": f"Bearer {first_token}"
            }
        )
    finally:
        scan_service.run_scanner = original_scanner
        scan_service.analyze_vulnerabilities = original_ai

    assert scan_response.status_code == 200

    scan_id = scan_response.json()["data"]["scan_id"]

    # Login as second user
    second_login = client.post(
        "/login",
        json={
            "email": "second_test@example.com",
            "password": "SecondPassword123!"
        }
    )

    assert second_login.status_code == 200
    second_token = second_login.json()["access_token"]

    # Second user attempts to access first user's scan
    response = client.get(
        f"/scans/{scan_id}",
        headers={
            "Authorization": f"Bearer {second_token}"
        }
    )

    assert response.status_code == 403
