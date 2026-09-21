from scanner.rules.security_misconfiguration import scan_security_misconfiguration


def write_test_file(tmp_path, source):
    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


def test_app_run_debug_true(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello"

app.run(debug=True)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Security Misconfiguration"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["confidence"] == 95
    assert findings[0]["code"] == "app.run(debug=True)"


def test_app_run_with_other_arguments_and_debug_true(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

app.run(host="0.0.0.0", port=5000, debug=True)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Security Misconfiguration"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["confidence"] == 95


def test_app_run_debug_false_is_safe(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

app.run(debug=False)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []


def test_app_run_without_debug_is_safe(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

app.run()
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []


def test_debug_variable_alone_is_safe(tmp_path):
    source = """
debug = True
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []


def test_variable_based_debug_is_not_detected(tmp_path):
    source = """
debug = True
app.run(debug=debug)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []


def test_generic_config_is_safe(tmp_path):
    source = """
config = {}
settings = load_settings()
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []
def test_app_run_with_other_arguments_debug_false_is_safe(tmp_path):
    source = """
from flask import Flask

app = Flask(__name__)

app.run(host="127.0.0.1", port=5000, debug=False)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_security_misconfiguration(file_path)

    assert findings == []