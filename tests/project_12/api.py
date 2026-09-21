from flask import request
import requests

user_url = request.args.get("url")
requests.get(user_url)
