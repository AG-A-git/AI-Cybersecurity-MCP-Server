from scanner.rules.sql import detect_sql_injection
def load_rules():
    """
    Load all vulnerability detection rules.
    """

    rules = [
        detect_sql_injection
    ]

    return rules

def run_all_rules(file_path, code):
    """
    Execute all vulnerability detection rules.
    """

    findings = []

    rules = load_rules()

    for rule in rules:

        result = rule(file_path, code)

        findings.extend(result)

    return findings

