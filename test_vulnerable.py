import sqlite3

username = input("Username: ")

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

query = "SELECT * FROM users WHERE username = '" + username + "'"

cursor.execute(query)

result = cursor.fetchall()

print(result)