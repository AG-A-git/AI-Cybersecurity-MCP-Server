
import json

from pydantic import BaseModel, ConfigDict, ValidationError


class AIAnalysis(BaseModel):
    """
    Validated structure for AI-generated vulnerability analysis.

    AI output is treated as untrusted data.
    """

    model_config = ConfigDict(
        extra="forbid"
    )

    explanation: str
    impact: str
    recommendation: str
    secure_practice: str


def parse_ai_response(response):
    """
    Parse and validate the structured response returned by Ollama.

    AI output is untrusted and must never be treated as executable
    instructions or authoritative risk information.
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

    # Remove Markdown code fences if the model adds them.
    if response.startswith("```json"):
        response = response[len("```json"):].strip()

    elif response.startswith("```"):
        response = response[len("```"):].strip()

    if response.endswith("```"):
        response = response[:-3].strip()

    try:
        data = json.loads(response)

    except json.JSONDecodeError as error:
        # Do not print the complete AI response.
        # It may contain source code, secrets, prompts,
        # or other sensitive information.
        raise ValueError(
            "AI returned invalid JSON."
        ) from error

    if not isinstance(data, dict):
        raise ValueError(
            "AI response must be a JSON object."
        )

    try:
        return AIAnalysis(**data)

    except ValidationError as error:
        raise ValueError(
            f"AI response is missing or has invalid fields: {error}"
        ) from error