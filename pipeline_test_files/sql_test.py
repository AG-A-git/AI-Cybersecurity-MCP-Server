def login(username):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    return query
