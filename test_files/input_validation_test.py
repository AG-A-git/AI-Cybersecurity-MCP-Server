from flask import request
import sqlite3
import os


connection = sqlite3.connect("test.db")
cursor = connection.cursor()

# Should NOT be detected
user_id = request.args.get("id")

# SHOULD be detected
cursor.execute(request.args.get("query"))

# SHOULD be detected
os.system(request.args.get("command"))

# Should NOT be detected
name = input("Enter your name: ")

print(name)