import sqlite3

user_id = input("Enter User ID: ")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Unsafe SQL query using string concatenation
query = "SELECT * FROM users WHERE id=" + user_id

cursor.execute(query)

print("Done")