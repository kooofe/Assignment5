from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime

app = Flask(__name__)

# Load RSA keys for RS256 signing/verification
with open("private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
with open("public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

# In‑memory user store (replace with DB in production)
users = {
    "admin": {"password": "admin123", "id": 1},
    "user":  {"password": "password",  "id": 2},
}
# Map username → user_id
user_ids = {u: info["id"] for u, info in users.items()}

# ------------------------------------------------------------------------------
# 1. Brute‑force Protection: Flask‑Limiter
# ------------------------------------------------------------------------------
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],  # Global defaults
    storage_uri="memory://"
)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Restrict to 5 attempts per minute per IP
def login():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    # Issue RS256‑signed JWT with 30‑minute expiration
    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"token": token}), 200

# ------------------------------------------------------------------------------
# 2. Secure Profile (prevent token‑hijacking & alg:none)
# ------------------------------------------------------------------------------
@app.route("/profile", methods=["GET"])
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # Only allow RS256 tokens—reject alg: none or any other
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        username = payload["user"]
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        return jsonify({"error": f"Unauthorized: {str(e)}"}), 401

    return jsonify({"message": f"Welcome {username}"}), 200

# ------------------------------------------------------------------------------
# 3. IDOR Protection
# ------------------------------------------------------------------------------
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        username = payload["user"]
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "Unauthorized"}), 401

    # Enforce that token’s user_id matches requested user_id
    if user_ids.get(username) != user_id:
        return jsonify({"error": "Access denied"}), 403

    return jsonify({"user_id": user_id, "role": "user"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
