# tests/test_app.py
import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as c:
        yield c

def test_login_no_json(client):
    res = client.post("/login")
    assert res.status_code == 400

def test_login_success(client):
    res = client.post("/login", json={"username": "user", "password": "password"})
    assert res.status_code == 200
    assert "token" in res.get_json()

def test_profile_unauthenticated(client):
    res = client.get("/profile")
    assert res.status_code == 401
