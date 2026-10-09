import json
import re
from typing import Any

import requests
from pydantic import ValidationError

from .config import (
    OLLAMA_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
    OLLAMA_TEMPERATURE,
    OLLAMA_TOP_P,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
    MAX_CODE_LENGTH,
)
from .models import VulnerabilityInput, AIAnalysisResponse
from .vulnerability_mapping import get_vulnerability_mapping
from .prompts import build_security_prompt


class OllamaClient:
    """
    Production Ollama client.

    Responsible only for communicating with Ollama.

    Scanner severity, confidence, risk score, and risk level
    remain authoritative outside the AI client.
    """

    def __init__(
        self,
        url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ):
        self.url = url if url is not None else OLLAMA_URL
        self.model = model if model is not None else OLLAMA_MODEL
        self.timeout = (
            timeout if timeout is not None else OLLAMA_TIMEOUT
        )

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to Ollama and return the generated response.
        """

        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")

        prompt = prompt.strip()

        if not prompt:
            raise ValueError("prompt cannot be empty")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": OLLAMA_TEMPERATURE,
                "top_p": OLLAMA_TOP_P,
                "num_ctx": OLLAMA_NUM_CTX,
                "num_predict": OLLAMA_NUM_PREDICT,
            },
        }

        response = requests.post(
            self.url,
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError(
                "Ollama returned an invalid response object"
            )

        result = data.get("response")

        if not isinstance(result, str):
            raise ValueError(
                "Ollama response field is missing or invalid"
            )

        result = result.strip()

        if not result:
            raise ValueError(
                "Ollama returned an empty response"
            )

        return result

    def health_check(self) -> str:
        """
        Check whether Ollama is reachable and the configured model
        is available.

        Returns:

            "ok"
                Ollama is reachable and the configured model exists.

            "unavailable"
                Ollama cannot be reached or returned an invalid response.

            "model_unavailable"
                Ollama is reachable but the configured model is not
                installed.
        """

        try:
            tags_url = self.url.replace(
                "/api/generate",
                "/api/tags",
            )

            response = requests.get(
                tags_url,
                timeout=self.timeout,
            )

            response.raise_for_status()

            data = response.json()

            if not isinstance(data, dict):
                return "unavailable"

            models = data.get("models", [])

            if not isinstance(models, list):
                return "unavailable"

            for model in models:
                if not isinstance(model, dict):
                    continue

                model_name = model.get("name")

                if model_name == self.model:
                    return "ok"

                if (
                    isinstance(model_name, str)
                    and model_name.split(":")[0]
                    == self.model.split(":")[0]
                ):
                    return "ok"

            return "model_unavailable"

        except requests.exceptions.RequestException:
            return "unavailable"

        except (ValueError, TypeError):
            return "unavailable"


def extract_json(text: str) -> dict[str, Any]:
    """
    Extract a JSON object from an AI response.

    Supports:
    - plain JSON
    - Markdown JSON code fences
    - JSON surrounded by other text
    - incomplete JSON with a missing final brace
    """

    if not text or not text.strip():
        raise ValueError("AI response was empty")

    text = text.strip()

    # 1. Direct JSON
    try:
        data = json.loads(text)

        if not isinstance(data, dict):
            raise ValueError(
                "AI response JSON must be an object"
            )

        return data

    except json.JSONDecodeError:
        pass

    # 2. Markdown JSON code fence
    cleaned = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )

    cleaned = re.sub(
        r"\s*```$",
        "",
        cleaned,
    ).strip()

    try:
        data = json.loads(cleaned)

        if not isinstance(data, dict):
            raise ValueError(
                "AI response JSON must be an object"
            )

        return data

    except json.JSONDecodeError:
        pass

    # 3. JSON surrounded by other text
    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start:end + 1]

        try:
            data = json.loads(candidate)

            if not isinstance(data, dict):
                raise ValueError(
                    "AI response JSON must be an object"
                )

            return data

        except json.JSONDecodeError:
            pass

    # 4. Missing final closing brace
    if start != -1:
        candidate = cleaned[start:].strip()

        if candidate.count("{") > candidate.count("}"):
            candidate += "}"

            try:
                data = json.loads(candidate)

                if not isinstance(data, dict):
                    raise ValueError(
                        "AI response JSON must be an object"
                    )

                return data

            except json.JSONDecodeError:
                pass

    raise ValueError(
        "AI response contained invalid or incomplete JSON"
    )


def classify_ai_error(exc: Exception) -> str:
    """
    Classify AI/Ollama failures into stable error categories.

    Categories:

    timeout
    connection_error
    request_error
    invalid_response
    invalid_json
    validation_error
    unexpected_error
    """

    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"

    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"

    if isinstance(exc, requests.exceptions.RequestException):
        return "request_error"

    if isinstance(exc, ValidationError):
        return "validation_error"

    if isinstance(exc, ValueError):
        message = str(exc).lower()

        if "json" in message:
            return "invalid_json"

        if "response" in message:
            return "invalid_response"

        return "validation_error"

    return "unexpected_error"


def calculate_risk_score(
    severity: str,
    confidence: float,
) -> float:
    """
    Calculate deterministic risk score.

    Scanner severity and confidence remain authoritative.
    """

    severity_scores = {
        "critical": 100,
        "high": 80,
        "medium": 60,
        "low": 40,
        "info": 20,
    }

    severity_key = severity.strip().lower()

    base_score = severity_scores.get(
        severity_key,
        0,
    )

    confidence = max(
        0.0,
        min(float(confidence), 100.0),
    )

    score = base_score * (
        confidence / 100.0
    )

    return round(score, 2)


def get_risk_level(score: float) -> str:
    """
    Convert numeric risk score into a risk level.
    """

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 40:
        return "Medium"

    if score >= 20:
        return "Low"

    return "Informational"


def limit_code_context(code: str) -> str:
    """
    Limit source-code size before sending it to the AI model.

    Large source files can exceed the model context window.

    The beginning of the finding is retained because it usually
    contains the vulnerable statement and surrounding context.
    """

    if not isinstance(code, str):
        raise TypeError("code must be a string")

    if len(code) <= MAX_CODE_LENGTH:
        return code

    truncated = code[:MAX_CODE_LENGTH]

    return (
        truncated
        + "\n\n"
        + "[CODE TRUNCATED FOR AI CONTEXT SAFETY]"
    )
def normalize_vulnerability(
    vulnerability: VulnerabilityInput | dict[str, Any],
) -> VulnerabilityInput:
    """Normalize a scanner finding supplied as a model or dictionary."""

    if isinstance(vulnerability, dict):
        vulnerability = VulnerabilityInput(**vulnerability)

    if not isinstance(vulnerability, VulnerabilityInput):
        raise TypeError(
            "vulnerability must be a VulnerabilityInput or dictionary"
        )

    return VulnerabilityInput(
        file=vulnerability.file.strip(),
        line=vulnerability.line,
        vulnerability=vulnerability.vulnerability.strip(),
        severity=vulnerability.severity.strip(),
        confidence=float(vulnerability.confidence),
        code=limit_code_context(vulnerability.code.strip()),
    )

def normalize_ai_response(
    data: dict[str, Any],
    vulnerability: VulnerabilityInput,
    expected_owasp: str | None = None,
    expected_cwe: str | None = None,
) -> AIAnalysisResponse:
    """
    Validate and normalize structured AI output.

    The AI provides explanation and recommendation.

    OWASP and CWE are taken from the deterministic vulnerability
    mapping so that the AI cannot override authoritative mappings.
    """

    if not isinstance(data, dict):
        raise ValueError(
            "AI response must be a JSON object"
        )

    explanation = data.get("explanation")
    recommendation = data.get("recommendation")

    if not isinstance(explanation, str):
        raise ValueError(
            "AI response explanation must be a string"
        )

    if not isinstance(recommendation, str):
        raise ValueError(
            "AI response recommendation must be a string"
        )

    explanation = explanation.strip()
    recommendation = recommendation.strip()

    if not explanation:
        raise ValueError(
            "AI response explanation cannot be empty"
        )

    if not recommendation:
        raise ValueError(
            "AI response recommendation cannot be empty"
        )

    return AIAnalysisResponse(
        explanation=explanation,
        recommendation=recommendation,
        owasp=expected_owasp,
        cwe=expected_cwe,
    )


def analyze_vulnerability(
    vulnerability: VulnerabilityInput,
) -> dict[str, Any]:
    """
    Complete AI vulnerability analysis pipeline.

    Pipeline:

    Scanner Finding
        ↓
    Normalize Input
        ↓
    Limit Context
        ↓
    Calculate Deterministic Risk
        ↓
    Vulnerability Mapping
        ↓
    Build Security Prompt
        ↓
    Ollama
        ↓
    Extract JSON
        ↓
    Validate Structured AI Response
        ↓
    Normalized Security Intelligence
    """

    vulnerability = normalize_vulnerability(
        vulnerability
    )

    # Deterministic risk calculation
    risk_score = calculate_risk_score(
        vulnerability.severity,
        vulnerability.confidence,
    )

    risk_level = get_risk_level(
        risk_score
    )

    # Deterministic OWASP/CWE mapping
    mapping = get_vulnerability_mapping(
        vulnerability.vulnerability
    )

    owasp = None
    cwe = None

    if mapping:
        owasp = mapping.get("owasp")
        cwe = mapping.get("cwe")

    # Centralized security prompt
    prompt = build_security_prompt(
        file=vulnerability.file,
        line=vulnerability.line,
        vulnerability=vulnerability.vulnerability,
        severity=vulnerability.severity,
        confidence=vulnerability.confidence,
        code=vulnerability.code,
        owasp=owasp,
        cwe=cwe,
    )

    try:
        client = OllamaClient()

        raw_response = client.generate(
            prompt
        )

        parsed_response = extract_json(
            raw_response
        )

        ai_response = normalize_ai_response(
            parsed_response,
            vulnerability,
            expected_owasp=owasp,
            expected_cwe=cwe,
        )

        return {
            "file": vulnerability.file,
            "line": vulnerability.line,
            "code": vulnerability.code,
            "vulnerability": vulnerability.vulnerability,
            "severity": vulnerability.severity,
            "confidence": vulnerability.confidence,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "owasp": owasp,
            "cwe": cwe,
            "ai_status": "completed",
            "ai_error_type": None,
            "ai_analysis": ai_response.model_dump(),
            "recommendation": ai_response.recommendation,
        }

    except Exception as exc:
        error_type = classify_ai_error(exc)

        if error_type == "timeout":
            recommendation = (
                "AI analysis service timed out."
            )

        elif error_type == "connection_error":
            recommendation = (
                "AI analysis service is unavailable."
            )

        elif error_type == "request_error":
            recommendation = (
                "AI analysis request failed."
            )

        elif error_type == "invalid_json":
            recommendation = (
                "AI returned invalid JSON."
            )

        elif error_type == "invalid_response":
            recommendation = (
                "AI returned an invalid response."
            )

        elif error_type == "validation_error":
            recommendation = (
                "AI returned invalid structured data."
            )

        else:
            recommendation = (
                "AI analysis failed safely."
            )

        return {
            "file": vulnerability.file,
            "line": vulnerability.line,
            "code": vulnerability.code,
            "vulnerability": vulnerability.vulnerability,
            "severity": vulnerability.severity,
            "confidence": vulnerability.confidence,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "owasp": owasp,
            "cwe": cwe,
            "ai_status": "failed",
            "ai_error_type": error_type,
            "ai_analysis": None,
            "recommendation": recommendation,
            "error": str(exc),
        }

def generate_response(prompt: str) -> str:
    """Generate a response using the configured Ollama client."""
    try:
        return OllamaClient().generate(prompt)
    except Exception as exc:
        raise RuntimeError(
            f"Ollama request failed: {exc}"
        ) from exc
