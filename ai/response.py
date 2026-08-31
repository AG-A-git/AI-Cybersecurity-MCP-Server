import json

from pydantic import BaseModel, ValidationError


class AIAnalysis(BaseModel):
    explanation: str
    impact: str
    recommendation: str
    secure_practice: str


def parse_ai_response(response):
    """
    Parse and validate the structured response returned by Ollama.
    """

    if not response or not response.strip():
        raise ValueError("AI returned an empty response.")

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
        print("\nInvalid AI JSON:")
        print(response)

        raise ValueError(
            f"AI returned invalid JSON: {error}"
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