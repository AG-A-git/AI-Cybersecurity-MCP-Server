from ai.risk_score import (
    calculate_risk,
    get_vulnerability_impact
)


# ------------------------------------------------------
# Impact Factor Tests
# ------------------------------------------------------

assert get_vulnerability_impact(
    "SQL Injection"
) == 1.15

assert get_vulnerability_impact(
    "Command Injection"
) == 1.15

assert get_vulnerability_impact(
    "SSRF"
) == 1.15

assert get_vulnerability_impact(
    "XSS"
) == 1.05

assert get_vulnerability_impact(
    "Weak Cryptography"
) == 1.05


# ------------------------------------------------------
# Risk Calculation Tests
# ------------------------------------------------------

sql_risk = calculate_risk(
    "High",
    90,
    "SQL Injection"
)

assert sql_risk == 77.62


xss_risk = calculate_risk(
    "High",
    90,
    "XSS"
)

assert xss_risk == 70.88


# ------------------------------------------------------
# Unknown Vulnerability
# ------------------------------------------------------

unknown_risk = calculate_risk(
    "High",
    90,
    "Unknown Vulnerability"
)

assert unknown_risk == 67.5


print(
    "All vulnerability impact risk tests PASSED!"
)