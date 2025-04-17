import os
import jwt
import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Load secret from environment (fallback to a constant if not set)
SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE_ME_TO_A_STRONG_SECRET")

# === Rate Limiting (Brute‐force Protection) ===
# Correct instantiation
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.json or {}
    uname, pwd = data.get("username"), data.get("password")
    # (replace with your own user lookup)
    if uname=="admin" and pwd=="admin123":
        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({"user": uname, "exp": exp},
                           SECRET_KEY, algorithm="HS256")  # :contentReference[oaicite:0]{index=0}
        return jsonify(token=token)
    return jsonify(error="Invalid credentials"), 401

@app.route("/profile")
def profile():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # :contentReference[oaicite:1]{index=1}
        return jsonify(message=f"Welcome {payload['user']}")
    except jwt.ExpiredSignatureError:
        return jsonify(error="Token expired"), 401
    except jwt.InvalidTokenError:
        return jsonify(error="Invalid token"), 401

@app.route("/users/<int:uid>")
def get_user(uid):
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify(error="Unauthorized"), 401

    # Simple IDOR check
    if payload["user"]=="admin" and uid==1 or payload["user"]=="user" and uid==2:
        return jsonify(user_id=uid, role="user")
    return jsonify(error="Access denied"), 403

if __name__=="__main__":
    app.run(debug=True)
