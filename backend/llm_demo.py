from ai.llm import OllamaClient


def main():
    client = OllamaClient()
    prompt = "Explain what SQL Injection is in two simple sentences."
    response = client.generate(prompt)

    print("\nAI Response:\n")
    print(response)


if __name__ == "__main__":
    main()
