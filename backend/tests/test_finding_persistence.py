from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import User, Project, Scan, Vulnerability
from services.scan_service import persist_findings


def test_persist_findings_preserves_scanner_evidence_and_ai_metadata(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'finding_persistence.db'}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    try:
        user = User(
            username="persistence_test_user",
            email="persistence_test@example.test",
            password_hash="test-hash",
        )
        db.add(user)
        db.flush()

        project = Project(
            project_name="Persistence Test Project",
            owner_id=user.id,
        )
        db.add(project)
        db.flush()

        scan = Scan(
            project_id=project.id,
            status="running",
        )
        db.add(scan)
        db.flush()

        finding = {
            "file": "src/security_test.py",
            "line": 42,
            "vulnerability": "SQL Injection",
            "severity": "High",
            "confidence": 90,
            "code": "cursor.execute(query)",
            "risk_score": 81.5,
            "owasp": "A03:2021",
            "cwe": "CWE-89",
            "explanation": "User-controlled input reaches a SQL query.",
            "impact": "An attacker may manipulate database queries.",
            "recommendation": "Use parameterized queries.",
        }

        count = persist_findings(db, scan.id, [finding])

        assert count == 1

        saved = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id)
            .one()
        )

        assert saved.file_name == finding["file"]
        assert saved.line_number == finding["line"]
        assert saved.vulnerability_type == finding["vulnerability"]
        assert saved.severity == finding["severity"]
        assert saved.confidence == finding["confidence"]
        assert saved.code == finding["code"]
        assert saved.risk_score == finding["risk_score"]
        assert saved.owasp_category == finding["owasp"]
        assert saved.cwe_id == finding["cwe"]
        assert saved.explanation == finding["explanation"]
        assert saved.impact == finding["impact"]
        assert saved.recommendation == finding["recommendation"]

    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
