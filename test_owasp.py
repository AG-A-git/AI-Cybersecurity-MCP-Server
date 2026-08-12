from ai.owasp import OWASP_MAPPING

finding = "SQL Injection"

print("Vulnerability:", finding)
print("OWASP ID:", OWASP_MAPPING[finding]["id"])
print("Category:", OWASP_MAPPING[finding]["category"])