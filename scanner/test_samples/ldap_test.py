from flask import request

username = request.args["username"]

query = "(uid=" + username + ")"