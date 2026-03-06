import requests

resp = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "llama3",
        "prompt": "Explain what a web enumeration scan is in cybersecurity.",
        "stream": False
    }
)

print(resp.json()["response"])