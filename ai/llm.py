# ======================================================
# AI / LLM Integration
# ======================================================

import json
import re
from typing import Any, Dict, Optional

import requests

from ai.models import (
    VulnerabilityInput,
    AIAnalysisResponse,
)

from ai.vulnerability_mapping import VULNERABILITY_MAPPING

try:
    from ai.normalization import normalize_vulnerability_type
except ImportError:
    normalize_vulnerability_type = None


# ======================================================
# Ollama Configuration
# ======================================================

OLLAMA_URL = "http://localhost:11434/api/generate"

OLLAMA_MODEL = "llama3.2"

OLLAMA_TIMEOUT = 60


# ======================================================
# Ollama Client
# ======================================================

class OllamaClient:

    def __init__(
        self,
        url: str = OLLAMA_URL,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ):
        self.url = url
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to Ollama and return the raw response.
        """

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:

            response = requests.post(
                self.url,
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()

            data = response.json()

            return data.get("response", "")

        except requests.exceptions.Timeout:

            raise TimeoutError(
                "Ollama request timed out."
            )

        except requests.exceptions.RequestException as exc:

            raise RuntimeError(
                f"Ollama request failed: {exc}"
            )


# ======================================================
# Default Ollama Client
# ======================================================

ollama_client = OllamaClient()


# ======================================================
# Backward-Compatible Generate Function
# ======================================================

def generate_response(
    prompt: str,
    client: Optional[OllamaClient] = None,
) -> str:
    """
    Generate a raw AI response.

    This function is kept for compatibility with
    ai/test_llm.py and other existing modules.
    """

    if client is None:
        client = ollama_client

    return client.generate(prompt)


# ======================================================
# JSON Extraction
# ======================================================

def extract_json(text: str) -> Dict[str, Any]:
    """
    Extract a JSON object from an AI response.

    Supports:
    - plain JSON
    - Markdown JSON code blocks
    - JSON surrounded by explanatory text
    """

    if not isinstance(text, str):
        raise ValueError(
            "AI response must be a string."
        )

    text = text.strip()

    if not text:
        raise ValueError(
            "AI response is empty."
        )

    # --------------------------------------------------
    # Remove Markdown code fences
    # --------------------------------------------------

    cleaned = re.sub(
        r"```(?:json)?",
        "",
        text,
        flags=re.IGNORECASE,
    )

    cleaned = cleaned.replace(
        "```",
        ""
    ).strip()

    # --------------------------------------------------
    # First attempt: entire response is JSON
    # --------------------------------------------------

    try:

        data = json.loads(cleaned)

        if not isinstance(data, dict):
            raise ValueError(
                "AI response JSON must be an object."
            )

        return data

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------
    # Second attempt: find JSON object inside response
    # --------------------------------------------------

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start == -1 or end == -1 or end <= start:

        raise ValueError(
            "No JSON object found in AI response."
        )

    json_text = cleaned[start:end + 1]

    try:

        data = json.loads(json_text)

    except json.JSONDecodeError as exc:

        raise ValueError(
            f"Invalid JSON in AI response: {exc}"
        )

    if not isinstance(data, dict):

        raise ValueError(
            "AI response JSON must be an object."
        )

    return data


# ======================================================
# Risk Score
# ======================================================

def calculate_risk_score(
    severity: str,
    confidence: float,
) -> float:
    """
    Calculate deterministic risk score.

    Severity weight:
        Critical = 1.00
        High     = 0.85
        Medium   = 0.60
        Low      = 0.30
    """

    severity_weights = {
        "critical": 1.00,
        "high": 0.85,
        "medium": 0.60,
        "low": 0.30,
    }

    normalized_severity = str(
        severity
    ).strip().lower()

    weight = severity_weights.get(
        normalized_severity,
        0.0,
    )

    confidence = float(confidence)

    confidence = max(
        0.0,
        min(100.0, confidence),
    )

    score = weight * confidence

    return round(
        score,
        2
    )


# ======================================================
# Risk Level
# ======================================================

def get_risk_level(
    risk_score: float,
) -> str:
    """
    Convert numerical risk score into a risk level.
    """

    if risk_score >= 90:
        return "Critical"

    if risk_score >= 75:
        return "High"

    if risk_score >= 50:
        return "Medium"

    if risk_score > 0:
        return "Low"

    return "Unknown"


# ======================================================
# Vulnerability Type Normalization
# ======================================================

VULNERABILITY_ALIASES = {

    "sqli": "SQL Injection",

    "sql injection vulnerability":
        "SQL Injection",

    "sql injection":
        "SQL Injection",

    "xss":
        "XSS",

    "cross site scripting":
        "XSS",

    "cross-site scripting":
        "XSS",

    "cross site scripting vulnerability":
        "XSS",

    "command injection":
        "Command Injection",

    "os command injection":
        "Command Injection",

    "os command execution":
        "Command Injection",

    "ldap injection":
        "LDAP Injection",

    "ldap injection vulnerability":
        "LDAP Injection",

    "hardcoded credentials":
        "Hardcoded Credentials/Secrets",

    "hardcoded password":
        "Hardcoded Credentials/Secrets",

    "hardcoded secret":
        "Hardcoded Credentials/Secrets",

    "hardcoded secrets":
        "Hardcoded Credentials/Secrets",

    "hardcoded credentials/secrets":
        "Hardcoded Credentials/Secrets",

    "weak cryptography":
        "Weak Cryptography",

    "weak encryption":
        "Weak Cryptography",

    "weak cryptographic algorithm":
        "Weak Cryptography",

    "broken access control":
        "Broken Access Control",

    "access control vulnerability":
        "Broken Access Control",

    "security misconfiguration":
        "Security Misconfiguration",

    "misconfiguration":
        "Security Misconfiguration",

    "insecure configuration":
        "Security Misconfiguration",

    "insecure authentication":
        "Insecure Authentication",

    "authentication weakness":
        "Insecure Authentication",

    "weak authentication":
        "Insecure Authentication",

    "insecure deserialization":
        "Insecure Deserialization",

    "unsafe deserialization":
        "Insecure Deserialization",

    "sensitive data exposure":
        "Sensitive Data Exposure",

    "sensitive information exposure":
        "Sensitive Data Exposure",

    "data exposure":
        "Sensitive Data Exposure",

    "ssrf":
        "SSRF",

    "server-side request forgery":
        "SSRF",

    "server side request forgery":
        "SSRF",
}


def normalize_type(value: str) -> str:
    """
    Normalize vulnerability names.

    Uses ai.normalization if available,
    otherwise falls back to local aliases.
    """

    if normalize_vulnerability_type is not None:

        try:

            return normalize_vulnerability_type(
                value
            )

        except ValueError:
            pass

    if not isinstance(value, str):

        raise ValueError(
            "Vulnerability type must be a string."
        )

    normalized = value.strip().lower()

    if not normalized:

        raise ValueError(
            "Vulnerability type cannot be empty."
        )

    # Canonical mapping
    for canonical in VULNERABILITY_MAPPING:

        if normalized == canonical.lower():

            return canonical

    # Alias mapping
    canonical = VULNERABILITY_ALIASES.get(
        normalized
    )

    if canonical:

        return canonical

    raise ValueError(
        f"Unknown vulnerability type: {value}"
    )


# ======================================================
# Prompt Builder
# ======================================================

def build_prompt(
    vulnerability: VulnerabilityInput,
) -> str:
    """
    Build a strict JSON-only prompt for the LLM.
    """

    vulnerability_type = normalize_type(
        vulnerability.vulnerability
    )

    prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

Analyze the following vulnerability.

File:
{vulnerability.file}

Line:
{vulnerability.line}

Vulnerability:
{vulnerability_type}

Severity:
{vulnerability.severity}

Confidence:
{vulnerability.confidence}

Code:
{vulnerability.code}

Return ONLY a valid JSON object.

Do not use Markdown.
Do not use ``` fences.
Do not add text before or after the JSON.

The JSON MUST contain exactly these fields:

{{
    "severity": "Critical",
    "explanation": "Detailed explanation of the vulnerability.",
    "impact": "Security impact of the vulnerability.",
    "recommendation": "Specific remediation recommendation."
}}

Rules:

1. severity must be one of:
   Critical, High, Medium, Low

2. explanation must explain why the code is vulnerable.

3. impact must explain the possible security consequences.

4. recommendation must explain how to fix the vulnerability.

5. Return valid JSON only.
"""

    return prompt.strip()


# ======================================================
# AI Analysis
# ======================================================

def analyze_vulnerability(
    vulnerability: VulnerabilityInput,
    client: Optional[OllamaClient] = None,
) -> Dict[str, Any]:
    """
    Analyze a vulnerability using the AI service.

    Always returns the structured vulnerability object,
    even when AI analysis fails.
    """

    # --------------------------------------------------
    # Normalize vulnerability type
    # --------------------------------------------------

    try:

        canonical_type = normalize_type(
            vulnerability.vulnerability
        )

    except ValueError:

        return {
            "file": vulnerability.file,
            "line": vulnerability.line,
            "code": vulnerability.code,
            "vulnerability": vulnerability.vulnerability,
            "severity": vulnerability.severity,
            "confidence": float(
                vulnerability.confidence
            ),
            "risk_score": 0,
            "risk_level": "Unknown",
            "owasp": None,
            "cwe": None,
            "ai_status": "invalid_vulnerability_type",
            "ai_analysis": None,
            "explanation": None,
            "impact": None,
            "recommendation":
                "Analysis unavailable because the vulnerability type is unsupported.",
        }

    # --------------------------------------------------
    # Calculate risk
    # --------------------------------------------------

    risk_score = calculate_risk_score(
        vulnerability.severity,
        vulnerability.confidence,
    )

    risk_level = get_risk_level(
        risk_score
    )

    # --------------------------------------------------
    # Vulnerability metadata
    # --------------------------------------------------

    mapping = VULNERABILITY_MAPPING.get(
        canonical_type,
        {}
    )

    owasp = mapping.get(
        "owasp"
    )

    cwe = mapping.get(
        "cwe"
    )

    # --------------------------------------------------
    # Base result
    # --------------------------------------------------

    result = {
        "file": vulnerability.file,
        "line": vulnerability.line,
        "code": vulnerability.code,
        "vulnerability": canonical_type,
        "severity": vulnerability.severity,
        "confidence": float(
            vulnerability.confidence
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "owasp": owasp,
        "cwe": cwe,
        "ai_status": "failed",
        "ai_analysis": None,
        "explanation": None,
        "impact": None,
        "recommendation": None,
    }

    # --------------------------------------------------
    # Build prompt
    # --------------------------------------------------

    try:

        prompt = build_prompt(
            vulnerability
        )

    except Exception as exc:

        print(
            f"Unexpected AI analysis error: {exc}"
        )

        result["recommendation"] = (
            "AI analysis could not be started."
        )

        return result

    # --------------------------------------------------
    # Call AI
    # --------------------------------------------------

    try:

        raw_response = generate_response(
            prompt,
            client=client,
        )

        print(
            "\nRaw AI Analysis:"
        )

        print(
            raw_response
        )

    except TimeoutError as exc:

        print(
            f"AI service failed: {exc}"
        )

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis service unavailable."
        )

        return result

    except Exception as exc:

        print(
            f"Unexpected AI analysis error: {exc}"
        )

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis service unavailable."
        )

        return result

    # --------------------------------------------------
    # Parse JSON
    # --------------------------------------------------

    try:

        ai_data = extract_json(
            raw_response
        )

    except ValueError as exc:

        print(
            f"AI response is not valid JSON: {exc}"
        )

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis response was invalid."
        )

        return result

    # --------------------------------------------------
    # Validate AI response
    # --------------------------------------------------

    try:

        validated = AIAnalysisResponse(
            **ai_data
        )

    except Exception as exc:

        print(
            f"AI response validation failed: {exc}"
        )

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis response failed validation."
        )

        return result

    # --------------------------------------------------
    # Successful AI analysis
    # --------------------------------------------------

    ai_analysis = (
        validated.model_dump()
        if hasattr(validated, "model_dump")
        else validated.dict()
    )

    result["ai_status"] = "success"

    result["ai_analysis"] = ai_analysis

    result["explanation"] = (
        ai_analysis.get(
            "explanation"
        )
    )

    result["impact"] = (
        ai_analysis.get(
            "impact"
        )
    )

    result["recommendation"] = (
        ai_analysis.get(
            "recommendation"
        )
    )

    # --------------------------------------------------
    # Use AI severity if valid
    # --------------------------------------------------

    ai_severity = ai_analysis.get(
        "severity"
    )

    if isinstance(
        ai_severity,
        str
    ):

        ai_severity = ai_severity.strip()

        if ai_severity in {
            "Critical",
            "High",
            "Medium",
            "Low",
        }:

            result["severity"] = ai_severity

    return result