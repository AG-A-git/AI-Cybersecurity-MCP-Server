
from ai.prompts import build_prompt
from ai.llm import OllamaClient


def main():
    details = {
        "file": "login.py",
        "line": 42,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": (
            'query = "SELECT * FROM users WHERE username=\'" '
            '+ username + "\'"'
        ),
    }

    prompt = build_prompt(details)
    client = OllamaClient()
    response = client.generate(prompt)

    print(response)


if __name__ == "__main__":
    main()