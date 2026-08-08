SEVERITY_SCORE = {
    "Critical": 95,
    "High": 80,
    "Medium": 55,
    "Low": 25
}


def calculate_risk(severity):

    severity = severity.strip().capitalize()

    return SEVERITY_SCORE.get(severity, 0)


def classify_risk(score):

    if score >= 90:
        return "Critical"

    elif score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    elif score >= 10:
        return "Low"

    return "Unknown"


if __name__ == "__main__":

    severity = "Critical"

    risk = calculate_risk(severity)

    print("Severity:", severity)
    print("Risk Score:", risk)
    print("Risk Level:", classify_risk(risk))