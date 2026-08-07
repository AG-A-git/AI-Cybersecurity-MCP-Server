from auth import create_access_token, verify_token

token = create_access_token(
    {
        "sub": "test@gmail.com"
    }
)

print("Generated Token:")
print(token)

print()

payload = verify_token(token)

print("Decoded Payload:")
print(payload)
