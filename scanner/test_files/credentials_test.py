password = "admin123"

API_KEY = "abcd123"

SECRET_KEY = "123456"

token = "xyz"

username = "admin"

if __name__ == "__main__":
    results = scan_credentials(
        "scanner/test_files/credentials_test.py"
    )

    for result in results:
        print(result)