import sqlite3
import hashlib


PASSWORD = "Admin@123456"


def get_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # SQL Injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    return cursor.fetchall()


def hash_password(password):
    # Weak Cryptography
    return hashlib.md5(password.encode()).hexdigest()


def process_input(request, cursor):
    # Improper Input Validation
    cursor.execute(request.args.get("query"))
    os.system(request.args.get("command"))


def main():
    username = input("Enter username: ")

    get_user(username)

    print(hash_password(PASSWORD))


if __name__ == "__main__":
    main()