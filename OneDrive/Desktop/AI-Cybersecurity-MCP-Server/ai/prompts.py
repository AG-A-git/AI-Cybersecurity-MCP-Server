"""
Prompt templates for AI vulnerability explanations.
"""

SQL_INJECTION_PROMPT = """
You are a cybersecurity expert.

A scanner has detected a possible SQL Injection vulnerability.

Provide:
1. What SQL Injection is.
2. Why it is dangerous.
3. How this vulnerability can affect the application.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""

XSS_PROMPT = """
You are a cybersecurity expert.

A scanner has detected a possible Cross-Site Scripting (XSS) vulnerability.

Provide:
1. What XSS is.
2. Why it is dangerous.
3. Possible impact on users.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""

COMMAND_INJECTION_PROMPT = """
You are a cybersecurity expert.

A scanner has detected a possible Command Injection vulnerability.

Explain:
1. What Command Injection is.
2. Why attackers use it.
3. Possible consequences.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""

HARDCODED_CREDENTIALS_PROMPT = """
You are a cybersecurity expert.

A scanner has detected hardcoded credentials.

Explain:
1. What hardcoded credentials are.
2. Why they are risky.
3. Possible security impact.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""
PROMPT_MAP = {
    "SQL Injection": SQL_INJECTION_PROMPT,
    "XSS": XSS_PROMPT,
    "Command Injection": COMMAND_INJECTION_PROMPT,
    "Hardcoded Credentials": HARDCODED_CREDENTIALS_PROMPT,
}
SQL_INJECTION_RECOMMENDATION = """
You are a cybersecurity expert.

A SQL Injection vulnerability has been detected.

Vulnerability Details:
{details}

Provide:
1. Recommended fix.
2. Secure coding practices.
3. Best practices to prevent this vulnerability.

Keep the response under 150 words.
"""

XSS_RECOMMENDATION = """
You are a cybersecurity expert.

A Cross-Site Scripting (XSS) vulnerability has been detected.

Vulnerability Details:
{details}

Provide:
1. Recommended fix.
2. Secure coding practices.
3. Best practices.

Keep the response under 150 words.
"""

COMMAND_INJECTION_RECOMMENDATION = """
You are a cybersecurity expert.

A Command Injection vulnerability has been detected.

Vulnerability Details:
{details}

Provide:
1. Recommended fix.
2. Secure coding practices.
3. Best practices.

Keep the response under 150 words.
"""

HARDCODED_CREDENTIALS_RECOMMENDATION = """
You are a cybersecurity expert.

Hardcoded credentials have been detected.

Vulnerability Details:
{details}

Provide:
1. Recommended fix.
2. Secure coding practices.
3. Best practices.

Keep the response under 150 words.
"""
RECOMMENDATION_MAP = {
    "SQL Injection": SQL_INJECTION_RECOMMENDATION,
    "XSS": XSS_RECOMMENDATION,
    "Command Injection": COMMAND_INJECTION_RECOMMENDATION,
    "Hardcoded Credentials": HARDCODED_CREDENTIALS_RECOMMENDATION,
}
BASE_PROMPT = """
You are a cybersecurity expert.

Analyze the given vulnerability and provide:

1. Explanation
2. Severity
3. Risk Score
4. OWASP Mapping
5. CWE Mapping
6. Recommendation
"""

SQL_INJECTION_PROMPT = BASE_PROMPT + """

Vulnerability: SQL Injection

Explain how SQL Injection works, its impact, and prevention methods.
"""

XSS_PROMPT = BASE_PROMPT + """

Vulnerability: XSS

Explain Cross-Site Scripting (XSS), its impact, and prevention methods.
"""

HARDCODED_CREDENTIALS_PROMPT = BASE_PROMPT + """

Vulnerability: Hardcoded Credentials

Explain why hardcoded credentials are dangerous and how to prevent them.
"""

def get_prompt(vulnerability):
    vulnerability = vulnerability.lower()

    if vulnerability == "sql injection":
        return SQL_INJECTION_PROMPT
    elif vulnerability == "xss":
        return XSS_PROMPT
    elif vulnerability == "hardcoded credentials":
        return HARDCODED_CREDENTIALS_PROMPT
    else:
        return BASE_PROMPT + f"\n\nVulnerability: {vulnerability}"