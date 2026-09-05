user_id = input("Enter ID: ")

query = "SELECT * FROM users WHERE id=%s"

cursor.execute(query, (user_id,))