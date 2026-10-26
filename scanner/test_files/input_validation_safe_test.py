from flask import request
import sqlite3
import os

cursor = sqlite3.connect("app.db").cursor()

user_id = request.args.get("id")

if not user_id.isdigit():
    return_value = "Invalid ID"

query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)


command = request.args.get("cmd")

if command in ["date", "uptime"]:
    os.system(command)
