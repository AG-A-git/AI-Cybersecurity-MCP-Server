from flask import request
import sqlite3
import os
cursor = sqlite3.connect("app.db").cursor()
cursor.execute(request.args.get("query"))
os.system(request.args.get("command"))

def process_age(age):
    return age + 10

user_age = input("Enter your age: ")
result = process_age(user_age)
print(result)