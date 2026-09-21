from scanner.rules.sensitive import scan_sensitive_data_exposure


def write_test_file(tmp_path, code):
    file_path = tmp_path / "test.py"
    file_path.write_text(code, encoding="utf-8")
    return str(file_path)


def test_password_printed_is_detected(tmp_path):
    code = """
password = "secret123"
print(password)
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Sensitive Data Exposure"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] >= 80


def test_secret_logged_is_detected(tmp_path):
    code = """
secret = "abc123"
logger.info(secret)
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert len(findings) == 1


def test_api_key_returned_is_detected(tmp_path):
    code = """
api_key = "abc123"
return_value = api_key
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert len(findings) == 0


def test_token_count_is_safe(tmp_path):
    code = """
token_count = 10
print(token_count)
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert findings == []


def test_normal_variable_is_safe(tmp_path):
    code = """
username = "alice"
print(username)
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert findings == []


def test_credit_card_printed_is_detected(tmp_path):
    code = """
credit_card = "4111111111111111"
print(credit_card)
"""
    file_path = write_test_file(tmp_path, code)

    findings = scan_sensitive_data_exposure(file_path)

    assert len(findings) == 1