from flask import request
import sqlite3

username = request.args.get("username")
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor = sqlite3.connect("app.db").cursor()
cursor.execute(query)
