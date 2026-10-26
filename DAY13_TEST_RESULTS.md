# Task 10 – Vulnerable and Safe Test Cases

## Objective

Validate that the cybersecurity scanner correctly detects implemented vulnerabilities in vulnerable code while avoiding false positives on safe code.

## Vulnerability Coverage

| Vulnerability | Vulnerable Case | Safe Case | Status |
|---|---|---|---|
| SQL Injection | Yes | Yes | PASS |
| XSS | Yes | Yes | PASS |
| Hardcoded Credentials / Secrets | Yes | Yes | PASS |
| Weak Cryptography | Yes | Yes | PASS |
| Input Validation | Yes | Yes | PASS |
| Command Injection | Yes | Yes | PASS |
| LDAP Injection | Yes | Yes | PASS |
| Insecure Deserialization | Yes | Yes | PASS |
| Security Misconfiguration | Yes | Yes | PASS |
| Authentication / Access Control | Yes | Yes | PASS |
| SSRF | Yes | Yes | PASS |
| Sensitive Data Exposure | Not implemented | Not implemented | N/A |

## Command Injection Verification

Safe file:

`test_files/safe/command_safe.py`

The safe example uses a static filename rather than user-controlled input.

Central scanner result:

```text
[]