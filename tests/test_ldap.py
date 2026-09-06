from scanner.rules.ldap import scan_ldap


def write_test_file(tmp_path, source):
    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


def test_ldap_concatenation_detected(tmp_path):
    source = """
from flask import request

username = request.args.get("username")
query = "(uid=" + username + ")"
ldap.search(query)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_ldap(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "LDAP Injection"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 85
    assert findings[0]["line_number"] == 5


def test_ldap_fstring_detected(tmp_path):
    source = """
from flask import request

username = request.args.get("username")
query = f"(uid={username})"
ldap.search(query)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_ldap(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "LDAP Injection"


def test_static_ldap_query_is_safe(tmp_path):
    source = """
query = "(uid=admin)"
ldap.search(query)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_ldap(file_path)

    assert findings == []


def test_ldap_connection_is_safe(tmp_path):
    source = """
import ldap

connection = ldap.initialize("ldap://localhost")
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_ldap(file_path)

    assert findings == []