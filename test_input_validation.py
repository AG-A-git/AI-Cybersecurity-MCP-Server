from pydantic import ValidationError
from ai.input import validate_vulnerability


# -------------------------
# TEST 1: Valid input
# -------------------------

valid_data = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}

try:
    result = validate_vulnerability(valid_data)
    print("VALID INPUT: PASSED")
    print(result)
except ValidationError as e:
    print("VALID INPUT: FAILED")
    print(e)


# -------------------------
# TEST 2: Missing vulnerability
# -------------------------

invalid_data_1 = {
    "file": "login.py",
    "line": 22,
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}

try:
    result = validate_vulnerability(invalid_data_1)
    print("MISSING VULNERABILITY: FAILED")
except ValidationError:
    print("MISSING VULNERABILITY: PASSED")


# -------------------------
# TEST 3: Missing severity
# -------------------------

invalid_data_2 = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "confidence": 95,
    "code": "cursor.execute(query)"
}

try:
    result = validate_vulnerability(invalid_data_2)
    print("MISSING SEVERITY: FAILED")
except ValidationError:
    print("MISSING SEVERITY: PASSED")
    # -------------------------
# TEST 4: Invalid confidence
# -------------------------

invalid_data_3 = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 150,
    "code": "cursor.execute(query)"
}

try:
    result = validate_vulnerability(invalid_data_3)
    print("INVALID CONFIDENCE: FAILED")
except ValidationError:
    print("INVALID CONFIDENCE: PASSED")
    invalid_data_4 = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": -10,
    "code": "cursor.execute(query)"
}

try:
    result = validate_vulnerability(invalid_data_4)
    print("NEGATIVE CONFIDENCE: FAILED")
except ValidationError:
    print("NEGATIVE CONFIDENCE: PASSED")