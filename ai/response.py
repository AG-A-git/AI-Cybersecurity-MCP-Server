import json
import re

from pydantic import ValidationError

from .models import AIAnalysisResponse


def extract_json_response(response: str) -> dict:
    """
    Extract a JSON object from an AI response.

    Handles:
    - plain JSON
    - Markdown JSON code fences
    - explanatory text around JSON
    - truncated responses where the final } is missing
    """

    if not isinstance(response, str):
        raise ValueError(
            "AI response must be a string."
        )

    if not response.strip():
        raise ValueError(
            "AI returned an empty response."
        )

    response = response.strip()

    # --------------------------------------------------------
    # Remove Markdown code fences
    # --------------------------------------------------------

    if response.startswith("```json"):
        response = response[len("```json"):].strip()

    elif response.startswith("```"):
        response = response[len("```"):].strip()

    if response.endswith("```"):
        response = response[:-3].strip()

    # --------------------------------------------------------
    # Try complete response first
    # --------------------------------------------------------

    try:
        data = json.loads(response)

        if isinstance(data, dict):
            return data

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------------
    # Find JSON object inside surrounding text
    # --------------------------------------------------------

    start = response.find("{")

    if start == -1:
        raise ValueError(
            "No JSON object found in AI response."
        )

    candidate = response[start:].strip()

    # Remove trailing Markdown fence if present.
    candidate = re.sub(
        r"```\s*$",
        "",
        candidate,
    ).strip()

    # --------------------------------------------------------
    # Try extracted JSON
    # --------------------------------------------------------

    try:
        data = json.loads(candidate)

        if isinstance(data, dict):
            return data

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------------
    # Handle truncated JSON.
    #
    # Llama may occasionally return the complete fields but
    # omit the final closing }.
    # --------------------------------------------------------

    if not candidate.endswith("}"):
        candidate += "}"

        try:
            data = json.loads(candidate)

            if isinstance(data, dict):
                return data

        except json.JSONDecodeError as error:
            raise ValueError(
                "AI returned incomplete JSON."
            ) from error

    raise ValueError(
        "AI returned invalid JSON."
    )


def parse_ai_response(response):
    """
    Parse and validate the structured response returned by Ollama.

    AI output is untrusted and must never be treated as
    executable instructions or authoritative risk information.
    """

    data = extract_json_response(response)

    try:
        return AIAnalysisResponse(**data)

    except ValidationError as error:
        raise ValueError(
            f"AI response is missing or has invalid fields: {error}"
        ) from error