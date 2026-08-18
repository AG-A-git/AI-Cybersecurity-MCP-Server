from backend.schemas import UserRegister

user = UserRegister(
    username="testuser",
    email="test@gmail.com",
    password="password123"
)

print(user)