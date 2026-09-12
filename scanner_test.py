import sqlite3

user_input = input("Username: ")
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
cursor.execute(query)

password = "secret123"
