
from scanner.rules.ssrf import detect_ssrf


def test_request_args_to_get_detected():
    code = '''
from flask import request
import requests

url = request.args.get("url")
response = requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"
    assert findings[0]["file_name"] == "app.py"
    assert findings[0]["line_number"] == 6
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == 90


def test_request_form_to_get_detected():
    code = '''
from flask import request
import requests

url = request.form.get("url")
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_values_to_get_detected():
    code = '''
from flask import request
import requests

url = request.values.get("url")
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1


def test_input_to_get_detected():
    code = '''
import requests

url = input("URL: ")
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_args_to_post_detected():
    code = '''
from flask import request
import requests

url = request.args.get("url")
requests.post(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_args_to_request_detected():
    code = '''
from flask import request
import requests

url = request.args.get("url")
requests.request("GET", url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_input_to_urllib_urlopen_detected():
    code = '''
from urllib import request

url = input("URL: ")
request.urlopen(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_static_url_ignored():
    code = '''
import requests

response = requests.get("https://example.com")
'''
    findings = detect_ssrf(code, "app.py")

    assert findings == []


def test_static_url_variable_ignored():
    code = '''
import requests

url = "https://example.com"
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert findings == []


def test_static_post_url_ignored():
    code = '''
import requests

requests.post("https://example.com/api")
'''
    findings = detect_ssrf(code, "app.py")

    assert findings == []


def test_unrelated_variable_ignored():
    code = '''
import requests

name = "hello"
requests.get(name)
'''
    findings = detect_ssrf(code, "app.py")

    assert findings == []


def test_request_args_multi_hop_to_get_detected():
    code = '''
from flask import request
import requests

url = request.args.get("url")
target = url
final_target = target
requests.get(final_target)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_args_indexed_access_detected():
    code = '''
from flask import request
import requests

url = request.args["url"]
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_json_indexed_access_detected():
    code = '''
from flask import request
import requests

url = request.json["url"]
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_headers_get_detected():
    code = '''
from flask import request
import requests

url = request.headers.get("X-Target")
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_requests_get_keyword_url_detected():
    code = '''
from flask import request
import requests

url = request.args.get("url")
requests.get(url=url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_get_json_payload_to_get_detected():
    code = '''
from flask import request
import requests

payload = request.get_json()
requests.get(payload)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"


def test_request_get_json_url_field_to_get_detected():
    code = '''
from flask import request
import requests

payload = request.get_json()
url = payload["url"]
requests.get(url)
'''
    findings = detect_ssrf(code, "app.py")

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SSRF"
