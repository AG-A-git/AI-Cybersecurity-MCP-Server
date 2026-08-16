import requests

from .models import VulnerabilityInput
from .risk_score import calculate_risk, classify_risk


# ======================================================
# Ollama Configuration
# ======================================================

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"


# ======================================================
# Ollama Client
# ======================================================

class OllamaClient:

    def __init__(self):
        self.url = OLLAMA_URL
        self.model = MODEL_NAME

    def generate(self, prompt):
        """
        Send a prompt to Ollama and return the AI response.
        """

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        try:

            response = requests.post(
                self.url,
                json=payload,
                timeout=120
            )

            response.raise_for_status()

            result = response.json()

            ai_response = result.get(
                "response",
                ""
            )

            if not ai_response:
                raise RuntimeError(
                    "Ollama returned an empty response."
                )

            return ai_response.strip()

        except requests.exceptions.Timeout as e:

            raise RuntimeError(
                "Ollama request timed out."
            ) from e

        except requests.exceptions.ConnectionError as e:

            raise RuntimeError(
                "Unable to connect to Ollama."
            ) from e

        except requests.exceptions.RequestException as e:

            raise RuntimeError(
                f"Ollama request failed: {e}"
            ) from e

        except Exception as e:

            raise RuntimeError(
                f"Ollama processing failed: {e}"
            ) from e


# ======================================================
# Generate AI Response
# ======================================================

def generate_response(prompt):
    """
    Wrapper around OllamaClient.
    """

    client = OllamaClient()

    return client.generate(prompt)


# ======================================================
# Check Ollama Connection
# ======================================================

def connect_ollama():
    """
    Check whether Ollama is running.
    """

    try:

        response = requests.get(
            "http://localhost:11434",
            timeout=5
        )

        return response.status_code == 200

    except requests.exceptions.RequestException:

        return False


# ======================================================
# Test Ollama Connection
# ======================================================

def test_connection():

    if connect_ollama():

        print(
            "Ollama connected successfully."
        )

        prompt = (
            "Explain SQL Injection in simple words."
        )

        response = generate_response(
            prompt
        )

        print("\nAI Response:")
        print(response)

    else:

        print(
            "Ollama connection failed."
        )


# ======================================================
# Generate Explanation
# ======================================================

def generate_explanation(
    vulnerability_name,
    severity,
    confidence,
    file,
    line,
    code
):
    """
    Generate a concise security explanation.
    """

    prompt = f"""
You are a cybersecurity vulnerability analyst.

Analyze ONLY the vulnerability described below.

Vulnerability: {vulnerability_name}
Severity: {severity}
Scanner Confidence: {confidence}
File: {file}
Line: {line}

Affected Code:
{code}

Explain:

1. What is wrong?
2. Why is it dangerous?
3. What could an attacker potentially do?

Important:
- Stay specific to the vulnerability type.
- Do not confuse SQL Injection with Command Injection.
- Do not invent facts that are not supported by the finding.
- Do not provide a remediation recommendation.
- Do not use headings.
- Do not use bullet points.
- Return only the explanation.
- Keep it concise.
"""

    return generate_response(prompt)


# ======================================================
# Generate Recommendation
# ======================================================

def generate_recommendation(
    vulnerability_name,
    severity,
    code
):
    """
    Generate a concise remediation recommendation.
    """

    prompt = f"""
You are a secure software development expert.

Provide a practical remediation recommendation for this vulnerability.

Vulnerability: {vulnerability_name}
Severity: {severity}

Affected Code:
{code}

Give an actionable recommendation explaining how a developer
should fix this vulnerability.

Examples:

SQL Injection:
Use parameterized queries or prepared statements.

XSS:
Use context-aware output encoding and safely handle untrusted input.

Hardcoded Credentials:
Move secrets to environment variables or a secure secrets manager.

Input Validation:
Validate and constrain untrusted input before processing.

Important:
- Return ONLY the recommendation.
- Do not explain the vulnerability.
- Do not use headings.
- Do not use bullet points.
- Do not invent variable names.
- Keep it concise.
"""

    return generate_response(prompt)


# ======================================================
# Complete AI Vulnerability Analysis
# ======================================================

def analyze_vulnerability(
    vulnerability: VulnerabilityInput
):
    """
    Analyze one standardized scanner vulnerability.

    Scanner failure and AI failure are independent.

    If the AI fails, the scanner information and
    deterministic risk information are still returned.
    """

    # --------------------------------------------------
    # Step 1: Read scanner information
    # --------------------------------------------------

    vulnerability_name = (
        vulnerability.vulnerability
    )

    severity = vulnerability.severity

    file = vulnerability.file

    line = vulnerability.line

    confidence = vulnerability.confidence

    code = vulnerability.code

    # --------------------------------------------------
    # Step 2: Calculate deterministic risk
    # --------------------------------------------------

    risk_score = calculate_risk(
        severity,
        confidence
    )

    risk_level = classify_risk(
        risk_score
    )

    # --------------------------------------------------
    # Step 3: Default AI status
    # --------------------------------------------------

    ai_status = "success"

    explanation = ""

    recommendation = ""

    # --------------------------------------------------
    # Step 4: Generate AI explanation
    # --------------------------------------------------

    try:

        explanation = generate_explanation(
            vulnerability_name,
            severity,
            confidence,
            file,
            line,
            code
        )

    except Exception as e:

        ai_status = "failed"

        explanation = (
            "AI analysis unavailable."
        )

        print(
            f"AI explanation failed: {e}"
        )

    # --------------------------------------------------
    # Step 5: Generate AI recommendation
    # --------------------------------------------------

    try:

        recommendation = generate_recommendation(
            vulnerability_name,
            severity,
            code
        )

    except Exception as e:

        ai_status = "failed"

        recommendation = (
            "AI remediation recommendation unavailable."
        )

        print(
            f"AI recommendation failed: {e}"
        )

    # --------------------------------------------------
    # Step 6: Return standardized result
    # --------------------------------------------------

    return {
        "file": file,
        "line": line,
        "vulnerability": vulnerability_name,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "ai_status": ai_status,
        "explanation": explanation,
        "recommendation": recommendation
    }


# ======================================================
# Direct Test
# ======================================================

if __name__ == "__main__":

    scanner_result = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)"
    }

    # --------------------------------------------------
    # Convert scanner dictionary into validated model
    # --------------------------------------------------

    vulnerability = VulnerabilityInput(
        **scanner_result
    )

    # --------------------------------------------------
    # Analyze vulnerability
    # --------------------------------------------------

    result = analyze_vulnerability(
        vulnerability
    )

    # --------------------------------------------------
    # Print result
    # --------------------------------------------------

    print(
        "\n=============================="
    )

    print(
        "AI VULNERABILITY ANALYSIS"
    )

    print(
        "=============================="
    )

    print("\nFile:")
    print(result["file"])

    print("\nLine:")
    print(result["line"])

    print("\nVulnerability:")
    print(result["vulnerability"])

    print("\nSeverity:")
    print(result["severity"])

    print("\nConfidence:")
    print(result["confidence"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nRisk Level:")
    print(result["risk_level"])

    print("\nAI Status:")
    print(result["ai_status"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nRecommendation:")
    print(result["recommendation"])