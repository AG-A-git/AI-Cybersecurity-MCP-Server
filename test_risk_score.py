from ai.risk_score import calculate_risk, classify_risk


# ==========================================
# Critical + 100% confidence
# ==========================================

score = calculate_risk(
    "Critical",
    100
)

print("Critical / 100%:", score)

assert score == 90


# ==========================================
# Critical + 95% confidence
# ==========================================

score = calculate_risk(
    "Critical",
    95
)

print("Critical / 95%:", score)

assert score == 85.5


# ==========================================
# High + 100% confidence
# ==========================================

score = calculate_risk(
    "High",
    100
)

print("High / 100%:", score)

assert score == 75


# ==========================================
# Medium + 100% confidence
# ==========================================

score = calculate_risk(
    "Medium",
    100
)

print("Medium / 100%:", score)

assert score == 50


# ==========================================
# Low + 100% confidence
# ==========================================

score = calculate_risk(
    "Low",
    100
)

print("Low / 100%:", score)

assert score == 25


# ==========================================
# Classification tests
# ==========================================

assert classify_risk(95) == "Critical"

assert classify_risk(80) == "High"

assert classify_risk(60) == "Medium"

assert classify_risk(30) == "Low"

assert classify_risk(10) == "Informational"


print("\nALL RISK TESTS PASSED")