from flask import Flask, request
from markupsafe import Markup
app = Flask(__name__)

@app.route('/search')
def search():
    name = request.args.get("name")
    return Markup("<h1>Hello " + name + "</h1>")
