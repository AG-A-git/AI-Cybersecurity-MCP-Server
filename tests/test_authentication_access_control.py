from scanner.rules.authentication_access_control import (
    scan_authentication_access_control
)


def write_test_file(tmp_path, source):
    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


# ============================================================
# Insecure Authentication Tests
# ============================================================

def test_weak_password_123456(tmp_path):
    source = """
def login(password):
    if password == "123456":
        return True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    auth_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Insecure Authentication"
    ]

    assert len(auth_findings) == 1
    assert auth_findings[0]["severity"] == "High"
    assert auth_findings[0]["confidence"] == 90


def test_weak_password_password(tmp_path):
    source = """
def login(password):
    if password == "password":
        return True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    auth_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Insecure Authentication"
    ]

    assert len(auth_findings) == 1
    assert auth_findings[0]["confidence"] == 90


def test_weak_password_admin(tmp_path):
    source = """
def login(password):
    if password == "admin":
        return True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    auth_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Insecure Authentication"
    ]

    assert len(auth_findings) == 1
    assert auth_findings[0]["confidence"] == 85


def test_proper_password_verification_is_safe(tmp_path):
    source = """
def login(password, hashed_password):
    if verify_password(password, hashed_password):
        return True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert not any(
        finding["vulnerability_type"] == "Insecure Authentication"
        for finding in findings
    )


def test_variable_password_comparison_is_safe(tmp_path):
    source = """
def login(password, stored_password):
    if password == stored_password:
        return True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert not any(
        finding["vulnerability_type"] == "Insecure Authentication"
        for finding in findings
    )


# ============================================================
# Broken Access Control Tests
# ============================================================

def test_delete_route_without_authorization(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

@app.delete("/users/<user_id>")
def delete_user(user_id):
    db.delete(user_id)
    return {"message": "deleted"}
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    access_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"]
        == "Potential Broken Access Control"
    ]

    assert len(access_findings) == 1
    assert access_findings[0]["severity"] == "High"
    assert access_findings[0]["confidence"] == 65


def test_delete_route_with_admin_dependency_is_safe(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

@app.delete("/users/<user_id>")
def delete_user(user_id, current_user=Depends(require_admin)):
    db.delete(user_id)
    return {"message": "deleted"}
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert not any(
        finding["vulnerability_type"]
        == "Potential Broken Access Control"
        for finding in findings
    )


def test_delete_route_with_check_admin_is_safe(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

@app.route("/admin/delete", methods=["DELETE"])
def delete_user():
    check_admin()
    db.delete(user_id)
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert not any(
        finding["vulnerability_type"]
        == "Potential Broken Access Control"
        for finding in findings
    )


def test_generic_delete_operation_is_not_flagged(tmp_path):
    source = """
def cleanup():
    db.delete(old_record)
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert not any(
        finding["vulnerability_type"]
        == "Potential Broken Access Control"
        for finding in findings
    )


# ============================================================
# Generic Safe Code
# ============================================================

def test_unrelated_code_is_safe(tmp_path):
    source = """
config = {}
settings = load_settings()
debug = True
"""

    file_path = write_test_file(tmp_path, source)
    findings = scan_authentication_access_control(file_path)

    assert findings == []