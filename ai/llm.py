import requests

from .prompts import build_prompt


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

        payload = {
                 "model": self.model,
                 "prompt": prompt,
                 "stream": False,
                 "format": "json"
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

            return f"Connection Error: {e}"

        except Exception as e:
            raise RuntimeError(
        f"Ollama request failed: {e}"
    ) from e


# ------------------------------------------------------
# Generate AI response
# ------------------------------------------------------

def generate_response(prompt):
    """
    Wrapper function used by explanation.py
    and recommendation.py.
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

def analyze_vulnerability(scanner_result):
    """
    Complete AI vulnerability analysis pipeline.
    """

    # IMPORTANT:
    # These imports are inside the function to avoid
    # circular imports between llm.py and explanation.py.

    from .explanation import ExplanationGenerator
    from .recommendation import RecommendationGenerator
    from .risk_score import calculate_risk
    from .mapping import get_mapping

    # --------------------------------------------------
    # Step 1: Get vulnerability
    # --------------------------------------------------

    vulnerability = scanner_result.get(
        "vulnerability",
        "Unknown"
    )

    # --------------------------------------------------
    # Step 2: Get severity
    # --------------------------------------------------

    severity = scanner_result.get(
        "severity",
        "Medium"
    )

    # --------------------------------------------------
    # Step 3: Calculate risk score
    # --------------------------------------------------

    risk_score = calculate_risk(severity)

    # --------------------------------------------------
    # Step 4: Get OWASP and CWE
    # --------------------------------------------------

    mapping = get_mapping(vulnerability)

    # --------------------------------------------------
    # Step 5: Generate explanation
    # --------------------------------------------------

    explanation_generator = ExplanationGenerator()

    explanation = explanation_generator.generate_explanation(
        vulnerability
    )

    # --------------------------------------------------
    # Step 6: Create finding
    # --------------------------------------------------

    finding = {
        "type": vulnerability,
        "file": scanner_result.get(
            "file",
            "Unknown"
        ),
        "line": scanner_result.get(
            "line",
            0
        ),
        "code": scanner_result.get(
            "code",
            ""
        )
    }

    # --------------------------------------------------
    # Step 7: Generate recommendation
    # --------------------------------------------------

    recommendation_generator = RecommendationGenerator()

    recommendation = recommendation_generator.generate_recommendation(
        finding
    )

    # --------------------------------------------------
    # Step 8: Return complete result
    # --------------------------------------------------

    return {
        "vulnerability": vulnerability,
        "severity": severity,
        "risk_score": risk_score,
        "owasp": mapping["owasp"],
        "cwe": mapping["cwe"],
        "explanation": explanation["explanation"],
        "recommendation": recommendation["recommendation"]
    }


# ------------------------------------------------------
# Test the complete pipeline
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
    result = analyze_vulnerability(scanner_result)

    print("\n==============================")
    print("AI VULNERABILITY ANALYSIS")
    print("==============================")

    print("\nVulnerability:")
    print(result["vulnerability"])

    print("\nSeverity:")
    print(result["severity"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nOWASP:")
    print(result["owasp"])

    print("\nCWE:")
    print(result["cwe"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nRecommendation:")
    print(result["recommendation"])