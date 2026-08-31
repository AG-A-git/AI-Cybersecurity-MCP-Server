# ======================================================
# AI / LLM Security Analysis
# ======================================================

import json
import requests

from pydantic import ValidationError

from .input import VulnerabilityInput
from .models import AIAnalysisResponse
from .risk_score import calculate_risk, classify_risk
from .vulnerability_mapping import get_vulnerability_mapping
from .normalization import normalize_vulnerability_type


# ======================================================
# Ollama Configuration
# ======================================================

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"


# ======================================================
# Ollama Client
# ======================================================

class OllamaClient:
    """
    Client for communicating with Ollama.
    """

    def __init__(
        self,
        url=OLLAMA_URL,
        model=MODEL_NAME
    ):
        self.url = url
        self.model = model

    def generate(self, prompt):
        """
        Send a prompt to Ollama and return the response.
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

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Ollama request timed out."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                "Unable to connect to Ollama."
            ) from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Ollama request failed: {exc}"
            ) from exc


# ======================================================
# Generate Response
# ======================================================

def generate_response(prompt):
    """
    Generate an AI response using Ollama.
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
# Generate AI Explanation
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
    Generate structured vulnerability analysis.

    The AI provides:

        - severity
        - explanation
        - recommendation

    The application provides:

        - vulnerability
        - OWASP
        - CWE
        - risk score
        - risk level
    """

    prompt = f"""
You are a cybersecurity vulnerability analysis engine.

Analyze ONLY the scanner finding below.

==================================================
SCANNER FINDING
==================================================

Vulnerability Type:
{vulnerability_name}

Scanner Severity:
{severity}

Scanner Confidence:
{confidence}

File:
{file}

Line:
{line}

Code:
{code}

==================================================
RULES
==================================================

Analyze only the supplied information.

Do not invent information.

Do not change the vulnerability type.

Do not invent:

- file names
- line numbers
- source code
- programming languages
- frameworks
- libraries
- databases
- application architecture
- functions
- variables

==================================================
DETERMINISTIC DATA
==================================================

The application determines:

- vulnerability type
- OWASP
- CWE
- risk score
- risk level

DO NOT calculate these values.

DO NOT return these values.

DO NOT invent OWASP categories.

DO NOT invent CWE identifiers.

DO NOT calculate risk scores.

==================================================
AI RESPONSIBILITIES
==================================================

Return only:

1. severity
2. explanation
3. recommendation

==================================================
SEVERITY
==================================================

Severity must be exactly one of:

Critical
High
Medium
Low

Use the scanner severity as the primary assessment.

==================================================
EXPLANATION
==================================================

Explain why the supplied finding represents
a security vulnerability.

Base the explanation only on:

- vulnerability type
- code
- scanner information

Do not fabricate missing details.

==================================================
RECOMMENDATION
==================================================

Provide a practical remediation recommendation.

Do not assume a programming language, framework,
database, or library unless explicitly provided.

==================================================
STRICT JSON OUTPUT
==================================================

Return ONLY one JSON object.

Do NOT return Markdown.

Do NOT use code fences.

Do NOT write an introduction.

Do NOT write:

Here is the output:

Do NOT write anything before the JSON.

Do NOT write anything after the JSON.

The JSON must contain EXACTLY these fields:

severity
explanation
recommendation

Use double quotes around JSON keys.

Use double quotes around JSON string values.

Do not use trailing commas.

==================================================
REQUIRED FORMAT
==================================================

{{
    "severity": "High",
    "explanation": "Explain why the supplied code is vulnerable.",
    "recommendation": "Explain how the vulnerability should be fixed."
}}

==================================================
FINAL INSTRUCTION
==================================================

Return ONLY the JSON object.

No OWASP.
No CWE.
No risk_score.
No risk_level.
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
You are a cybersecurity remediation expert.

Vulnerability:
{vulnerability_name}

Severity:
{severity}

Code:
{code}

Provide a practical remediation recommendation.

Do not invent application details.

Return only the recommendation.
"""

    return generate_response(prompt)


# ======================================================
# Extract JSON Object
# ======================================================

def extract_json_object(text):
    """
    Extract JSON from an AI response.

    Handles responses such as:

    Here is the output:

    {{
        "severity": "High",
        "explanation": "...",
        "recommendation": "..."
    }}
    """

    if not isinstance(text, str):
        raise ValueError(
            "AI response must be a string."
        )

    text = text.strip()

    # Try parsing the complete response first.
    try:
        return json.loads(text)

    except json.JSONDecodeError:
        pass

    # Find the JSON object inside extra text.
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise json.JSONDecodeError(
            "No JSON object found in AI response.",
            text,
            0
        )

    json_text = text[start:end + 1]

    return json.loads(json_text)


# ======================================================
# Analyze Vulnerability
# ======================================================

def analyze_vulnerability(
    vulnerability: VulnerabilityInput
):
    """
    Complete security analysis pipeline.

    Scanner Finding
          ↓
    Normalization
          ↓
    OWASP/CWE Mapping
          ↓
    Risk Calculation
          ↓
    Llama Analysis
          ↓
    AI Validation
          ↓
    Final Security Result
    """

    # ==================================================
    # Scanner information
    # ==================================================

    original_vulnerability_name = (
        vulnerability.vulnerability
    )

    scanner_severity = vulnerability.severity

    file = vulnerability.file

    line = vulnerability.line

    confidence = vulnerability.confidence

    code = vulnerability.code


    # ==================================================
    # Normalize vulnerability
    # ==================================================

    try:

        vulnerability_name = (
            normalize_vulnerability_type(
                original_vulnerability_name
            )
        )

    except ValueError as exc:

        return {
            "file": file,
            "line": line,
            "code": code,
            "vulnerability": (
                original_vulnerability_name
            ),
            "severity": scanner_severity,
            "confidence": confidence,
            "risk_score": 0,
            "risk_level": "Unknown",
            "owasp": None,
            "cwe": None,
            "ai_status": (
                "invalid_vulnerability_type"
            ),
            "ai_analysis": None,
            "recommendation": (
                "Analysis unavailable because "
                "the vulnerability type is unsupported."
            ),
            "error": str(exc)
        }


    # ==================================================
    # OWASP / CWE mapping
    # ==================================================

    mapping = get_vulnerability_mapping(
        vulnerability_name
    )

    if mapping:

        mapped_owasp = mapping["owasp"]
        mapped_cwe = mapping["cwe"]

    else:

        mapped_owasp = None
        mapped_cwe = None


    # ==================================================
    # Deterministic risk calculation
    # ==================================================

    try:

        risk_score = calculate_risk(
            scanner_severity,
            confidence,
            vulnerability_name
        )

        risk_level = classify_risk(
            risk_score
        )

    except ValueError as exc:

        return {
            "file": file,
            "line": line,
            "code": code,
            "vulnerability": vulnerability_name,
            "severity": scanner_severity,
            "confidence": confidence,
            "risk_score": 0,
            "risk_level": "Unknown",
            "owasp": mapped_owasp,
            "cwe": mapped_cwe,
            "ai_status": "invalid_risk_input",
            "ai_analysis": None,
            "recommendation": (
                "Analysis unavailable because "
                "the risk input is invalid."
            ),
            "error": str(exc)
        }


    # ==================================================
    # Initialize AI result
    # ==================================================

    ai_status = "success"

    ai_analysis = None

    recommendation = (
        "AI recommendation unavailable."
    )


    # ==================================================
    # Llama analysis
    # ==================================================

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
        # Extract JSON
        # ----------------------------------------------

        parsed_ai_analysis = extract_json_object(
            raw_ai_analysis
        )


        # ----------------------------------------------
        # Validate AI response
        # ----------------------------------------------

        validated_ai_analysis = (
            AIAnalysisResponse(
                **parsed_ai_analysis
            )
        )


        # ----------------------------------------------
        # Store AI result
        # ----------------------------------------------

        ai_analysis = (
            validated_ai_analysis.model_dump()
        )

        recommendation = (
            validated_ai_analysis.recommendation
        )


    # ==================================================
    # Invalid JSON
    # ==================================================

    except json.JSONDecodeError as exc:

        ai_status = "failed"

        print(
            f"AI response is not valid JSON: {exc}"
        )

        ai_analysis = None

        recommendation = (
            "AI analysis response was invalid."
        )


    # ==================================================
    # AI schema validation failure
    # ==================================================

    except ValidationError as exc:

        ai_status = "failed"

        print(
            f"AI response validation failed: {exc}"
        )

        ai_analysis = None

        recommendation = (
            "AI analysis response failed validation."
        )


    # ==================================================
    # Ollama failure
    # ==================================================

    except RuntimeError as exc:

        ai_status = "failed"

        print(
            f"AI service failed: {exc}"
        )

        ai_analysis = None

        recommendation = (
            "AI analysis service unavailable."
        )


    # ==================================================
    # Unexpected failure
    # ==================================================

    except Exception as exc:

        ai_status = "failed"

        print(
            f"Unexpected AI analysis error: {exc}"
        )

        ai_analysis = None

        recommendation = (
            "AI analysis failed."
        )


    # ==================================================
    # Final Security Response
    # ==================================================

    return {
        "file": file,
        "line": line,

        # Preserve vulnerable source code.
        "code": code,

        # Canonical vulnerability name.
        "vulnerability": vulnerability_name,

        # Scanner information.
        "severity": scanner_severity,
        "confidence": confidence,

        # Deterministic risk.
        "risk_score": risk_score,
        "risk_level": risk_level,

        # Centralized OWASP/CWE mapping.
        "owasp": mapped_owasp,
        "cwe": mapped_cwe,

        # AI status.
        "ai_status": ai_status,

        # AI-generated analysis.
        "ai_analysis": ai_analysis,

        # Final recommendation.
        "recommendation": recommendation
    }


# ======================================================
# End of File
# ======================================================