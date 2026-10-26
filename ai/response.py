
import json
import re

from pydantic import ValidationError

from .models import AIAnalysis


def extract_json_response(response: str) -> dict:
    """
    Extract a JSON object from an AI response.

    Supports:
    - Plain JSON
    - Markdown JSON code fences
    - Explanatory text before or after JSON
    - A missing final closing brace when the JSON is otherwise valid
    """

    if not isinstance(response, str):
        raise ValueError("AI response must be a string.")

    if not response.strip():
        raise ValueError("AI returned an empty response.")

    response = response.strip()

    # Remove an optional Markdown code fence.
    if response.startswith("```json"):
        response = response[len("```json"):].strip()
    elif response.startswith("```"):
        response = response[len("```"):].strip()

    if response.endswith("```"):
        response = response[:-3].strip()

    # Accept a complete JSON object directly.
    try:
        data = json.loads(response)

        if isinstance(data, dict):
            return data

    except json.JSONDecodeError:
        pass

    # Find the first JSON object in the response.
    start = response.find("{")

    if start == -1:
        raise ValueError("No JSON object found in AI response.")

    # Find the matching closing brace while respecting quoted
    # strings, escaped quotes, and braces inside string values.
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(response)):
        char = response[index]

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False

            continue

        if char == '"':
            in_string = True

        elif char == "{":
            depth += 1

        elif char == "}":
            depth -= 1

            if depth < 0:
                raise ValueError("AI returned invalid JSON.")

            if depth == 0:
                candidate = response[start:index + 1]

                try:
                    data = json.loads(candidate)

                except json.JSONDecodeError as error:
                    raise ValueError(
                        "AI returned invalid JSON."
                    ) from error

                if not isinstance(data, dict):
                    raise ValueError(
                        "AI response must be a JSON object."
                    )

                return data

    # Recover a missing final brace only if adding exactly one
    # brace produces a valid JSON object.
    candidate = response[start:].strip()

    try:
        data = json.loads(candidate + "}")

    except json.JSONDecodeError as error:
        raise ValueError(
            "AI returned incomplete JSON."
        ) from error

    if not isinstance(data, dict):
        raise ValueError("AI response must be a JSON object.")

    return data


def parse_ai_response(response):
    """
    Parse and validate the structured response returned by Ollama.

    AI output is untrusted and must never be treated as executable
    instructions or authoritative risk information.
    """

    data = extract_json_response(response)

    try:
        return AIAnalysis(**data)

    except ValidationError as error:
        raise ValueError(
            f"AI response is missing or has invalid fields: {error}"
        ) from error
