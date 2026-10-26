def show_password_message():
    password_message = "Please enter your password"
    print(password_message)


def get_username_message():
    message = "Your username and password are required."
    return message


def normal_hash_example(data):
    # This is only a demonstration of a string containing "md5".
    algorithm_name = "md5"
    return algorithm_name


def safe_user_input():
    username = input("Enter your username: ")

    # No database query or dangerous operation is performed.
    print("Hello", username)


def main():
    show_password_message()
    print(get_username_message())
    print(normal_hash_example("test"))
    safe_user_input()


if __name__ == "__main__":
    main()

def show_password_message():
    password_message = "Please enter your password"
    print(password_message)