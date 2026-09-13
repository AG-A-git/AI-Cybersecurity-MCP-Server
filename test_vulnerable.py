username = input("Enter username: ")

query = "SELECT * FROM users WHERE name = '" + username + "'"

print(query)