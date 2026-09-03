"""
Prompt templates for AI vulnerability analysis.
"""

BASE_PROMPT = """
You are a cybersecurity expert.

Analyze the following vulnerability.

Provide:

1. Explanation
2. Impact
3. Recommendation
4. Best Practice

Keep the response clear, simple, and technically accurate.
"""

SQL_INJECTION_PROMPT = """
You are a cybersecurity expert.

A scanner has detected a possible SQL Injection vulnerability.

Provide:

1. What SQL Injection is.
2. Why it is dangerous.
3. The possible impact on the application.
4. Recommended remediation.
5. Secure coding best practices.

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
4. Recommended remediation.
5. Secure coding best practices.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""

COMMAND_INJECTION_PROMPT = """
You are a cybersecurity expert.

A scanner has detected a possible Command Injection vulnerability.

Provide:

1. What Command Injection is.
2. Why it is dangerous.
3. Possible consequences.
4. Recommended remediation.
5. Secure coding best practices.

Vulnerability Details:
{details}

Keep the explanation simple and under 150 words.
"""

HARDCODED_CREDENTIALS_PROMPT = """
You are a cybersecurity expert.

A scanner has detected hardcoded credentials.

Provide:

1. What hardcoded credentials are.
2. Why they are risky.
3. Possible security impact.
4. Recommended remediation.
5. Secure coding best practices.

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


def get_prompt(vulnerability):
    """
    Return the appropriate prompt template
    for a vulnerability type.
    """

    for name, prompt in PROMPT_MAP.items():

        if name.lower() == vulnerability.lower():
            return prompt

    return BASE_PROMPT + "\n\nVulnerability: {details}"


def build_prompt(scanner_result):
    """
    Build a dynamic prompt from scanner JSON.

    Args:
        scanner_result (dict):
            Vulnerability information from the scanner.

    Returns:
        str:
            Complete prompt ready to send to Ollama.
    """

    vulnerability = scanner_result.get(
        "vulnerability",
        "Unknown"
    )

    file_name = scanner_result.get(
        "file",
        "Unknown"
    )

    line = scanner_result.get(
        "line",
        "Unknown"
    )

    severity = scanner_result.get(
        "severity",
        "Unknown"
    )

    confidence = scanner_result.get(
        "confidence",
        "Unknown"
    )

    code = scanner_result.get(
        "code",
        "Not provided"
    )

    details = f"""
Vulnerability: {vulnerability}
Severity: {severity}
Confidence: {confidence}%
File: {file_name}
Line: {line}

Vulnerable Code:
{code}
"""

    prompt_template = get_prompt(vulnerability)

    return prompt_template.format(
        details=details
    )
# ------------------------------------------------------
# Recommendation prompts
# ------------------------------------------------------

SQL_INJECTION_RECOMMENDATION = """
You are a cybersecurity expert.

A SQL Injection vulnerability has been detected.

Vulnerability Details:
{details}

Provide:

1. Recommended fix.
2. Secure coding practices.
3. Best practices to prevent SQL Injection.

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
3. Best practices to prevent XSS.

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
3. Best practices to prevent Command Injection.

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
3. Best practices to prevent hardcoded credentials.

Keep the response under 150 words.
"""


RECOMMENDATION_MAP = {
    "SQL Injection": SQL_INJECTION_RECOMMENDATION,
    "XSS": XSS_RECOMMENDATION,
    "Command Injection": COMMAND_INJECTION_RECOMMENDATION,
    "Hardcoded Credentials": HARDCODED_CREDENTIALS_RECOMMENDATION,
}
STRUCTURED_ANALYSIS_PROMPT = """
You are a cybersecurity code analysis assistant.

Analyze the following security finding detected by a vulnerability scanner.

Vulnerability: {vulnerability}
Severity: {severity}
Scanner confidence: {confidence}%
File: {file}
Line: {line}

Vulnerable code:
{code}

Return ONLY valid JSON.

Do not use Markdown.
Do not use ```json.
Do not include any text before or after the JSON.

Return exactly these fields:

{{
    "explanation": "Explain why the provided code is vulnerable.",
    "impact": "Explain the potential security impact.",
    "recommendation": "Explain how the vulnerability should be fixed.",
    "secure_practice": "Give the most relevant secure coding practice."
}}

Rules:

1. Base the analysis only on the provided vulnerability and code.
2. Do not invent application details that were not provided.
3. Keep the explanation technically accurate.
4. Keep the impact specific to the vulnerability.
5. Give practical remediation advice.
6. Do not calculate or invent a risk score.
7. Do not invent an OWASP category or CWE.
8. IMPORTANT JSON RULES:

- Return a single JSON object.
- All string values MUST use valid JSON double-quoted strings.
- Escape any double quotes that appear inside string values.
- Do not include newline characters inside JSON string values.
- Do not use Markdown.
- Do not use code fences.
- Do not add comments.
"""


def build_structured_analysis_prompt(scanner_result):
    return STRUCTURED_ANALYSIS_PROMPT.format(
        vulnerability=scanner_result.get(
            "vulnerability",
            "Unknown"
        ),
        severity=scanner_result.get(
            "severity",
            "Unknown"
        ),
        confidence=scanner_result.get(
            "confidence",
            "Unknown"
        ),
        file=scanner_result.get(
            "file",
            "Unknown"
        ),
        line=scanner_result.get(
            "line",
            "Unknown"
        ),
        code=scanner_result.get(
            "code",
            "Not provided"
        )
    )