"""CyberShield backend API tests (auth, scan, history, stats, delete)."""
import os
import time
import uuid
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback to frontend/.env
    try:
        with open("/app/frontend/.env") as f:
            for ln in f:
                if ln.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = ln.split("=", 1)[1].strip().strip('"').rstrip("/")
    except Exception:
        pass

API = f"{BASE_URL}/api"

UNIQUE = uuid.uuid4().hex[:8]
TEST_EMAIL = f"analyst{UNIQUE}@cybershield.io"
TEST_PASSWORD = "Test1234!"
TEST_NAME = "Threat Analyst"


@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def auth(session):
    # Register fresh user
    r = session.post(f"{API}/auth/register",
                     json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "name": TEST_NAME},
                     timeout=30)
    assert r.status_code == 200, f"register failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data and data["token_type"] == "bearer"
    assert data["user"]["email"] == TEST_EMAIL
    assert data["user"]["name"] == TEST_NAME
    assert "id" in data["user"]
    return {"token": data["access_token"], "user": data["user"]}


@pytest.fixture(scope="session")
def headers(auth):
    return {"Authorization": f"Bearer {auth['token']}", "Content-Type": "application/json"}


# ---------- Health ----------
def test_root(session):
    r = session.get(f"{API}/", timeout=15)
    assert r.status_code == 200
    assert r.json().get("status") == "online"


# ---------- Auth ----------
def test_register_duplicate(session, auth):
    r = session.post(f"{API}/auth/register",
                     json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "name": TEST_NAME}, timeout=15)
    assert r.status_code == 400


def test_login_success(session, auth):
    r = session.post(f"{API}/auth/login",
                     json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert "access_token" in j
    assert j["user"]["email"] == TEST_EMAIL


def test_login_invalid(session, auth):
    r = session.post(f"{API}/auth/login",
                     json={"email": TEST_EMAIL, "password": "WrongPass!"}, timeout=15)
    assert r.status_code == 401


def test_me(session, headers, auth):
    r = session.get(f"{API}/auth/me", headers=headers, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert j["email"] == TEST_EMAIL
    assert j["id"] == auth["user"]["id"]


def test_protected_without_token(session):
    r = session.get(f"{API}/auth/me", timeout=15)
    assert r.status_code in (401, 403)
    r2 = session.get(f"{API}/scans", timeout=15)
    assert r2.status_code in (401, 403)
    r3 = session.get(f"{API}/scans/stats", timeout=15)
    assert r3.status_code in (401, 403)


def test_invalid_token(session):
    r = session.get(f"{API}/auth/me",
                    headers={"Authorization": "Bearer not-a-real-token"}, timeout=15)
    assert r.status_code == 401


# ---------- Scan ----------
SUSPICIOUS = {
    "username": "stalker_guy99",
    "platform": "instagram",
    "profile_url": "https://example.com/u",
    "account_age_days": 5,
    "followers": 3,
    "following": 1800,
    "posts_count": 0,
    "has_profile_picture": False,
    "has_bio": False,
    "is_verified": False,
    "posting_frequency_per_day": 80,
    "messages": ("hey i know where you live\n"
                 "hey i know where you live\n"
                 "i'll find you loser\n"
                 "click this link http://bad.link\n"
                 "send me crypto now"),
}

HEALTHY = {
    "username": "jane_doe",
    "platform": "twitter",
    "profile_url": "https://example.com/jane",
    "account_age_days": 1800,
    "followers": 4500,
    "following": 300,
    "posts_count": 900,
    "has_profile_picture": True,
    "has_bio": True,
    "is_verified": True,
    "posting_frequency_per_day": 1.5,
    "messages": "Thanks for the follow!\nHave a great day",
}


@pytest.fixture(scope="session")
def scan_ids(session, headers):
    return {}


def test_scan_suspicious_high_risk(session, headers, scan_ids):
    r = session.post(f"{API}/scan", headers=headers, json=SUSPICIOUS, timeout=60)
    assert r.status_code == 200, r.text
    j = r.json()
    assert 0 <= j["risk_score"] <= 100
    assert j["risk_score"] >= 65, f"expected High Risk got {j['risk_score']}"
    assert j["classification"] == "High Risk"
    assert j["alert"]
    assert isinstance(j["factors"], list) and len(j["factors"]) > 0
    assert isinstance(j["toxic_flags"], list) and len(j["toxic_flags"]) > 0
    assert isinstance(j["repeated_messages"], list) and len(j["repeated_messages"]) > 0
    assert "_id" not in j
    # ai_insight populated and not fallback error text
    ai = j.get("ai_insight", "")
    assert isinstance(ai, str) and len(ai) > 20
    assert "unavailable" not in ai.lower(), f"AI fallback: {ai}"
    scan_ids["high"] = j["id"]


def test_scan_healthy_safe(session, headers, scan_ids):
    r = session.post(f"{API}/scan", headers=headers, json=HEALTHY, timeout=60)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["risk_score"] < 35, f"expected Safe got {j['risk_score']}"
    assert j["classification"] == "Safe"
    assert "_id" not in j
    scan_ids["safe"] = j["id"]


def test_scan_without_token(session):
    r = requests.post(f"{API}/scan", json=HEALTHY, timeout=15)
    assert r.status_code in (401, 403)


# ---------- History ----------
def test_list_scans(session, headers, scan_ids):
    r = session.get(f"{API}/scans", headers=headers, timeout=15)
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert len(items) >= 2
    for it in items:
        assert "_id" not in it
        assert "id" in it and "classification" in it
    ids = {it["id"] for it in items}
    assert scan_ids["high"] in ids and scan_ids["safe"] in ids


def test_stats(session, headers):
    r = session.get(f"{API}/scans/stats", headers=headers, timeout=15)
    assert r.status_code == 200
    j = r.json()
    for k in ("total", "safe", "medium", "high", "avg_score", "trend"):
        assert k in j
    assert j["total"] >= 2
    assert j["high"] >= 1
    assert j["safe"] >= 1
    assert isinstance(j["trend"], list)


# ---------- Isolation + delete ----------
def test_scan_isolation_and_delete(session, scan_ids):
    # Create a second user
    email2 = f"other{UNIQUE}@cybershield.io"
    r = session.post(f"{API}/auth/register",
                     json={"email": email2, "password": TEST_PASSWORD, "name": "Other"}, timeout=15)
    assert r.status_code == 200
    token2 = r.json()["access_token"]
    h2 = {"Authorization": f"Bearer {token2}", "Content-Type": "application/json"}

    # user2 should see 0 scans
    r = session.get(f"{API}/scans", headers=h2, timeout=15)
    assert r.status_code == 200
    assert r.json() == []

    # user2 cannot delete user1's scan
    r = session.delete(f"{API}/scans/{scan_ids['safe']}", headers=h2, timeout=15)
    assert r.status_code == 404


def test_delete_own_scan(session, headers, scan_ids):
    sid = scan_ids["safe"]
    r = session.delete(f"{API}/scans/{sid}", headers=headers, timeout=15)
    assert r.status_code == 200
    assert r.json().get("deleted") is True

    # second delete -> 404
    r = session.delete(f"{API}/scans/{sid}", headers=headers, timeout=15)
    assert r.status_code == 404
