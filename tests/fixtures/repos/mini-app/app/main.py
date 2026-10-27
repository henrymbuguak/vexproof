import examplelib


def handler(body: str) -> object:
    return examplelib.parse(body)
