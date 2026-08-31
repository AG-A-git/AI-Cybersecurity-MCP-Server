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
            response = requests.post(self.url, json=payload)
            response.raise_for_status()

            result = response.json()

            return result.get("response", "").strip()

        except requests.exceptions.RequestException as e:
            return f"Connection Error: {e}"

        except Exception as e:
            return f"Unexpected Error: {e}"