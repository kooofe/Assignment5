import requests

# Replace with an actual token captured from the /login endpoint.
token = "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIn0."

headers = {
    "Authorization": f"Bearer {token}"
}

url = "http://localhost:5000/profile"

response = requests.get(url, headers=headers)

print("Response from /profile when using the captured token:")
print(response.text)
