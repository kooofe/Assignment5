import subprocess

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


# 4. Command Injection Endpoint (Remote Code Execution)
@app.route('/run', methods=['GET'])
def run_cmd():
    """
    Dangerous endpoint that executes any shell command supplied via ?cmd=...
    e.g.: GET /run?cmd=ls /etc
    """
    cmd = request.args.get('cmd')
    if not cmd:
        return "No cmd parameter provided", 400
    try:
        # WARNING: shell=True + unvalidated input → RCE vulnerability
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return jsonify({
            "cmd": cmd,
            "output": output
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "cmd": cmd,
            "error": e.output
        }), 500


if __name__ == '__main__':
    app.run(debug=True)

