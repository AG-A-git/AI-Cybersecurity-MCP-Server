import sqlite3

query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)