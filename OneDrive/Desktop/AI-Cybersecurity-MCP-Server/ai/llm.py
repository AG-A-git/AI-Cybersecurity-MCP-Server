import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"


class OllamaClient:

    def __init__(self):
        self.url = OLLAMA_URL
        self.model = MODEL_NAME

    def generate(self, prompt):
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

            return result.get("response", "").strip()

        except requests.exceptions.RequestException as e:
            return f"Connection Error: {e}"

        except Exception as e:
            return f"Unexpected Error: {e}"


def generate_response(prompt):
    """
    Wrapper function used by explanation.py
    and recommendation.py.
    """

    client = OllamaClient()

    return client.generate(prompt)


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


def test_connection():

    if connect_ollama():

        print("Ollama connected successfully.")

        prompt = "Explain SQL Injection in simple words."

        response = generate_response(prompt)

        print("\nAI Response:")
        print(response)

    else:

        print("Ollama connection failed.")


if __name__ == "__main__":
    test_connection()