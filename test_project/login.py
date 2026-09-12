import sqlite3

user_input = input("Username: ")
cursor = sqlite3.connect("database.db").cursor()
cursor.execute("SELECT * FROM users WHERE name = " + user_input)

password = "secret123"
