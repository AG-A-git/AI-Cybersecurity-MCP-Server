import time
import requests
from ai.prompts import build_security_prompt
from ai.config import (
    OLLAMA_MODEL, OLLAMA_NUM_CTX, OLLAMA_NUM_PREDICT,
    OLLAMA_TEMPERATURE, OLLAMA_TOP_P,
)

prompt = build_security_prompt(
    file="test.py",
    line=10,
    vulnerability="SQL Injection",
    severity="High",
    confidence=95,
    code="query = SQL + user_input",
)

payload = {
    "model": OLLAMA_MODEL,
    "prompt": prompt,
    "stream": False,
    "format": "json",
    "options": {
        "num_ctx": OLLAMA_NUM_CTX,
        "num_predict": OLLAMA_NUM_PREDICT,
        "temperature": OLLAMA_TEMPERATURE,
        "top_p": OLLAMA_TOP_P,
    },
}

print("Prompt characters:", len(prompt), flush=True)
start = time.perf_counter()
try:
    r = requests.post(
        "http://localhost:11434/api/generate",
        json=payload,
        timeout=90,
    )
    print("HTTP:", r.status_code, flush=True)
    print("Seconds:", round(time.perf_counter() - start, 2))
    print("Response:", r.text[:1500])
    r.raise_for_status()
except Exception as e:
    print("ERROR:", type(e).__name__, str(e))
    print("Seconds:", round(time.perf_counter() - start, 2))
    if getattr(e, "response", None) is not None:
        print("Body:", e.response.text[:1500])
