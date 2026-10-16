import json

import pytest
import requests

from ai.llm import extract_json, classify_ai_error


def test_extracts_plain_json():
    assert extract_json('{"explanation": "Valid"}') == {
        "explanation": "Valid"
    }


def test_extracts_json_from_markdown_fence():
    response = '```json\n{"explanation": "Valid"}\n```'

    assert extract_json(response) == {"explanation": "Valid"}


def test_extracts_json_surrounded_by_text():
    response = 'Model response:\n{"explanation": "Valid"}\nEnd'

    assert extract_json(response) == {"explanation": "Valid"}


def test_recovers_missing_final_brace():
    assert extract_json('{"explanation": "Valid"') == {
        "explanation": "Valid"
    }


@pytest.mark.parametrize(
    "response",
    [
        "",
        "   ",
        "not JSON",
        "[]",
        '"a JSON string"',
        '{"explanation": ',
    ],
)
def test_rejects_invalid_json_responses(response):
    with pytest.raises(ValueError):
        extract_json(response)


def test_classifies_timeout():
    assert classify_ai_error(
        requests.exceptions.Timeout()
    ) == "timeout"


def test_classifies_connection_error():
    assert classify_ai_error(
        requests.exceptions.ConnectionError()
    ) == "connection_error"


def test_classifies_invalid_json():
    assert classify_ai_error(
        ValueError("AI response contained invalid JSON")
    ) == "invalid_json"