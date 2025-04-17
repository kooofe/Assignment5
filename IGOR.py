import requests

print("Testing IDOR on /users/<user_id> ...")

# Test a range of user_id values, adjust the range as needed.
for user_id in range(1, 6):
    url = f"http://localhost:5000/users/{user_id}"
    response = requests.get(url)
    print(f"Response for user_id = {user_id}:")
    print(response.text)
    print("-" * 40)
