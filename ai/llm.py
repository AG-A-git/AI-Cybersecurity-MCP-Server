import json
import requests

from pydantic import ValidationError

from .models import VulnerabilityInput, AIAnalysisResponse
from .risk_score import calculate_risk, classify_risk
from .vulnerability_mapping import get_vulnerability_mapping


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
# Generate Response
# ======================================================

def generate_response(prompt):
    """
    Send prompt to Ollama.
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
# Generate Structured Security Analysis
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
    Ask Llama 3 to analyze a scanner finding.

    Llama must return JSON containing:

        severity
        risk_score
        owasp
        cwe
        explanation
        recommendation
    """

    prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

Analyze ONLY the security finding provided below.

Do not invent information that is not supported by the
scanner finding or supplied code.

SCANNER FINDING
---------------

File: {file}

Line: {line}

Vulnerability: {vulnerability_name}

Scanner Severity: {severity}

Scanner Confidence: {confidence}

Code:
{code}


TASK
----

Analyze the provided finding and return:

1. Security severity
2. Risk score from 0 to 100
3. OWASP Top 10 mapping
4. CWE mapping
5. Security explanation
6. Practical remediation recommendation


OUTPUT FORMAT
-------------

Return ONLY valid JSON.

Do NOT return Markdown.

Do NOT use ```json.

Do NOT put any text before the JSON.

Do NOT put any text after the JSON.

Use exactly these fields:

{{
    "severity": "High",
    "risk_score": 85,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-89",
    "explanation": "Explain why the provided code is vulnerable.",
    "recommendation": "Explain how the vulnerability should be fixed."
}}


IMPORTANT RULES
---------------

- risk_score MUST be an integer between 0 and 100.
- severity must describe the security impact.
- OWASP must correspond to the vulnerability.
- CWE must correspond to the vulnerability.
- Do not invent an OWASP category.
- Do not invent a CWE.
- Do not change the vulnerability type.
- Base your analysis only on the supplied finding and code.
- Keep the explanation technically accurate.
- Keep the recommendation practical.
- Return valid JSON only.
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
    Generate a remediation recommendation.
    """

    prompt = f"""
You are a secure software development expert.

Provide a practical remediation recommendation for the
following vulnerability.

Vulnerability:
{vulnerability_name}

Severity:
{severity}

Affected Code:
{code}

Requirements:

- Explain how a developer should fix the vulnerability.
- Keep the recommendation technically accurate.
- Do not invent application details.
- Return ONLY the recommendation.
- Do not use Markdown headings.
- Keep it concise.
"""

    return generate_response(prompt)


# ======================================================
# Complete Vulnerability Analysis
# ======================================================

def analyze_vulnerability(
    vulnerability: VulnerabilityInput
):
    """
    Complete security analysis pipeline.

    Flow:

        Scanner Finding
              ↓
        Input Validation
              ↓
        Risk Calculation
              ↓
        Central OWASP/CWE Mapping
              ↓
        Llama 3
              ↓
        JSON Parsing
              ↓
        AI Response Validation
              ↓
        Final Result
    """

    # --------------------------------------------------
    # STEP 1
    # Read validated scanner information
    # --------------------------------------------------

    vulnerability_name = vulnerability.vulnerability

    scanner_severity = vulnerability.severity

    file = vulnerability.file

    line = vulnerability.line

    confidence = vulnerability.confidence

    code = vulnerability.code


    # --------------------------------------------------
    # STEP 2
    # Calculate deterministic risk
    # --------------------------------------------------

    risk_score = calculate_risk(
        scanner_severity,
        confidence
    )

    risk_level = classify_risk(
        risk_score
    )


    # --------------------------------------------------
    # STEP 3
    # Get centralized OWASP/CWE mapping
    # --------------------------------------------------

    mapping = get_vulnerability_mapping(
        vulnerability_name
    )

    if mapping:

        mapped_owasp = mapping["owasp"]

        mapped_cwe = mapping["cwe"]

    else:

        mapped_owasp = None

        mapped_cwe = None


    # --------------------------------------------------
    # STEP 4
    # Initialize AI result
    # --------------------------------------------------

    ai_status = "success"

    ai_analysis = None

    recommendation = ""


    # --------------------------------------------------
    # STEP 5
    # Ask Llama 3 for analysis
    # --------------------------------------------------

    try:

        raw_ai_analysis = generate_explanation(
            vulnerability_name,
            scanner_severity,
            confidence,
            file,
            line,
            code
        )

        print("\nRaw AI Analysis:")

        print(raw_ai_analysis)


        # ----------------------------------------------
        # Parse JSON
        # ----------------------------------------------

        parsed_ai_analysis = json.loads(
            raw_ai_analysis
        )


        # ----------------------------------------------
        # Validate LLM response
        # ----------------------------------------------

        validated_ai_analysis = AIAnalysisResponse(
            **parsed_ai_analysis
        )


        # ----------------------------------------------
        # Apply centralized OWASP/CWE mapping
        # ----------------------------------------------

        if mapped_owasp and mapped_cwe:

            validated_ai_analysis.owasp = (
                mapped_owasp
            )

            validated_ai_analysis.cwe = (
                mapped_cwe
            )


        # ----------------------------------------------
        # Store validated AI response
        # ----------------------------------------------

        ai_analysis = validated_ai_analysis


    # --------------------------------------------------
    # JSON validation failure
    # --------------------------------------------------

    except json.JSONDecodeError as e:

        ai_status = "failed"

        print(
            f"AI response is not valid JSON: {e}"
        )

        ai_analysis = None


    # --------------------------------------------------
    # Pydantic validation failure
    # --------------------------------------------------

    except ValidationError as e:

        ai_status = "failed"

        print(
            f"AI response validation failed: {e}"
        )

        ai_analysis = None


    # --------------------------------------------------
    # Ollama failure
    # --------------------------------------------------

    except RuntimeError as e:

        ai_status = "failed"

        print(
            f"AI service failed: {e}"
        )

        ai_analysis = None


    # --------------------------------------------------
    # Unexpected error
    # --------------------------------------------------

    except Exception as e:

        ai_status = "failed"

        print(
            f"Unexpected AI analysis error: {e}"
        )

        ai_analysis = None


    # --------------------------------------------------
    # STEP 6
    # Generate remediation recommendation
    # --------------------------------------------------

    try:

        recommendation = generate_recommendation(
            vulnerability_name,
            scanner_severity,
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
    # STEP 7
    # Convert validated AI response to dictionary
    # --------------------------------------------------

    if ai_analysis is not None:

        ai_analysis_data = (
            ai_analysis.model_dump()
        )

    else:

        ai_analysis_data = None


    # --------------------------------------------------
    # STEP 8
    # Return final standardized result
    # --------------------------------------------------

    return {

        # Scanner information
        "file": file,

        "line": line,

        "vulnerability": vulnerability_name,

        "severity": scanner_severity,

        "confidence": confidence,


        # Deterministic risk
        "risk_score": risk_score,

        "risk_level": risk_level,


        # AI status
        "ai_status": ai_status,


        # Validated AI analysis
        "ai_analysis": ai_analysis_data,


        # Recommendation
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
    # Validate scanner result
    # --------------------------------------------------

    try:

        vulnerability = VulnerabilityInput(
            **scanner_result
        )

    except ValidationError as e:

        print(
            "Scanner input validation failed:"
        )

        print(e)

        raise SystemExit(1)


    # --------------------------------------------------
    # Analyze vulnerability
    # --------------------------------------------------

    result = analyze_vulnerability(
        vulnerability
    )


    # --------------------------------------------------
    # Print final result
    # --------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "AI VULNERABILITY ANALYSIS"
    )

    print(
        "========================================"
    )

    print("\nFile:")

    print(result["file"])


    print("\nLine:")

    print(result["line"])


    print("\nVulnerability:")

    print(result["vulnerability"])


    print("\nScanner Severity:")

    print(result["severity"])


    print("\nConfidence:")

    print(result["confidence"])


    print("\nDeterministic Risk Score:")

    print(result["risk_score"])


    print("\nRisk Level:")

    print(result["risk_level"])


    print("\nAI Status:")

    print(result["ai_status"])


    print("\nValidated AI Analysis:")

    print(
        json.dumps(
            result["ai_analysis"],
            indent=4
        )
    )


    print("\nRecommendation:")

    print(result["recommendation"])