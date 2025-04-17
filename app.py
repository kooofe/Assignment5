from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)
# Using a weak key intentionally for demonstration purposes
SECRET_KEY = "weakkey"

# Sample user database
users = {
    "admin": "admin123",
    "user": "password"
}


# 1. Login Endpoint (Vulnerable to brute-force attacks and weak JWT protection)
@app.route('/login', methods=['POST', 'GET'])
def login():
    data = request.get_json()
    if not data:
        return "Missing JSON data", 400

    username = data.get("username")
    password = data.get("password")

    if username in users and users[username] == password:
        # Create a JWT token with no expiration and using HS256
        token = jwt.encode({"user": username}, SECRET_KEY, algorithm="HS256")
        return jsonify({"token": token})

    return "Unauthorized", 401

# 2. Profile Endpoint (Vulnerable to token hijacking and alg: none attacks)
@app.route('/profile')
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # Insecurely allow "none" by adding it to the allowed algorithms. Do NOT use in production!
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"], options={"verify_signature": False})
        user = payload.get("user")
    except Exception as e:
        return f"Token error: {e}", 401
    return f"Welcome {user}"


# 3. Insecure Direct Object Reference (IDOR) Endpoint
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # This endpoint does not perform any authorization checks.
    # An attacker can modify user_id in the URL to access data not associated with their account.
    return jsonify({"user_id": user_id, "role": "user"})


if __name__ == '__main__':
    app.run(debug=True)
