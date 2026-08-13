import requests

from .prompts import build_prompt
from .models import VulnerabilityInput
from .risk_score import calculate_risk, classify_risk


# ------------------------------------------------------
# Ollama configuration
# ------------------------------------------------------

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"


# ------------------------------------------------------
# Ollama Client
# ------------------------------------------------------

class OllamaClient:

    def __init__(self):
        self.url = OLLAMA_URL
        self.model = MODEL_NAME

    def generate(self, prompt):
        """
        Send a prompt to Ollama and return
        the generated text response.
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

            return result.get("response", "")

        except requests.exceptions.RequestException as e:

            raise RuntimeError(
                f"Ollama unavailable: {e}"
            ) from e

        except Exception as e:

            raise RuntimeError(
                f"Ollama request failed: {e}"
            ) from e


# ------------------------------------------------------
# Generate AI response
# ------------------------------------------------------

def generate_response(prompt):
    """
    Wrapper function used by explanation.py,
    recommendation.py, and the AI analysis pipeline.
    """

    client = OllamaClient()

    return client.generate(prompt)


# ------------------------------------------------------
# Check Ollama connection
# ------------------------------------------------------

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


# ------------------------------------------------------
# Test Ollama connection
# ------------------------------------------------------

def test_connection():

    if connect_ollama():

        print("Ollama connected successfully.")

        prompt = "Explain SQL Injection in simple words."

        response = generate_response(prompt)

        print("\nAI Response:")
        print(response)

    else:

        print("Ollama connection failed.")


# ------------------------------------------------------
# Complete AI vulnerability analysis
# ------------------------------------------------------

def analyze_vulnerability(
    vulnerability: VulnerabilityInput
):
    """
    Analyze one standardized scanner vulnerability.

    Input:
        VulnerabilityInput

    Output:
        Structured AI analysis dictionary.
    """

    # --------------------------------------------------
    # Step 1: Read scanner information
    # --------------------------------------------------

    vulnerability_name = vulnerability.vulnerability
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
    # Step 3: Build AI prompt
    # --------------------------------------------------

    prompt = f"""
Analyze this cybersecurity vulnerability.

Vulnerability: {vulnerability_name}
Severity: {severity}
Scanner Confidence: {confidence}
File: {file}
Line: {line}

Affected Code:
{code}

Provide a concise security explanation.

The explanation must answer:
1. What is wrong?
2. Why is it dangerous?
3. What could an attacker do?

Return ONLY the explanation.
Do not include headings.
Do not include bullet points.
Do not include recommendations.
Keep it to 2-4 sentences.
"""

    # --------------------------------------------------
    # Step 4: Ask Ollama
    # --------------------------------------------------

    response = generate_response(prompt)

    # --------------------------------------------------
    # Step 5: Return structured result
    # --------------------------------------------------

    return {
        "file": file,
        "line": line,
        "vulnerability": vulnerability_name,
        "severity": severity,
        "confidence": confidence,
        "code": code,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": response
    }


# ------------------------------------------------------
# Direct test
# ------------------------------------------------------

if __name__ == "__main__":

    scanner_result = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)"
    }

    # Convert scanner dictionary into
    # the validated AI input model.
    vulnerability = VulnerabilityInput(
        **scanner_result
    )

    result = analyze_vulnerability(
        vulnerability
    )

    print("\n==============================")
    print("AI VULNERABILITY ANALYSIS")
    print("==============================")

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

    print("\nExplanation:")
    print(result["ai_response"])