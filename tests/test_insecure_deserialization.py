from scanner.rules.insecure_deserialization import scan_insecure_deserialization


def write_test_file(tmp_path, source):
    file_path = tmp_path / "test.py"
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


def test_pickle_loads_untrusted_data(tmp_path):
    source = """
import pickle
from flask import request

data = request.data
obj = pickle.loads(data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Insecure Deserialization"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 90
    assert findings[0]["line_number"] == 6


def test_pickle_load_untrusted_file(tmp_path):
    source = """
import pickle
from flask import request

file = request.files["data"]
obj = pickle.load(file)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Insecure Deserialization"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 90
    assert findings[0]["line_number"] == 6


def test_pickle_loads_input(tmp_path):
    source = """
import pickle

data = input()
obj = pickle.loads(data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Insecure Deserialization"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 90
    assert findings[0]["line_number"] == 5


def test_json_loads_is_safe(tmp_path):
    source = """
import json
from flask import request

data = request.data
obj = json.loads(data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert findings == []


def test_static_json_is_safe(tmp_path):
    source = """
import json

data = '{"name": "Alice"}'
obj = json.loads(data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert findings == []
def test_yaml_safe_load_is_safe(tmp_path):
    source = """
import yaml
from flask import request

data = request.data
obj = yaml.safe_load(data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert findings == []
def test_direct_request_data_to_pickle_detected(tmp_path):
    source = """
import pickle
from flask import request

obj = pickle.loads(request.data)
"""

    file_path = write_test_file(tmp_path, source)

    findings = scan_insecure_deserialization(file_path)

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Insecure Deserialization"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 90
    assert findings[0]["line_number"] == 5