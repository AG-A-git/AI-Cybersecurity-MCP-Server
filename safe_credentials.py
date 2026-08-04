import os

password = os.getenv("DB_PASSWORD")
api_key = os.getenv("API_KEY")

print("Credentials loaded securely")