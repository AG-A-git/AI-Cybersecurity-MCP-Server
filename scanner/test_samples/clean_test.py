def add_numbers(a, b):
    return a + b

message = "Hello, world!"
print(message)

def calculate_total(price, quantity):
    if price < 0 or quantity < 0:
        raise ValueError("Invalid input")

    return price * quantity


def main():
    price = 100
    quantity = 2

    total = calculate_total(price, quantity)
    print("Total:", total)


if __name__ == "__main__":
    main()