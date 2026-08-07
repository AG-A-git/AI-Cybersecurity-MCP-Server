from prompts import get_prompt
from llm import generate_response


prompt = get_prompt("SQL Injection")

response = generate_response(prompt)

print(response)