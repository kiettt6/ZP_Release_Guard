"""Tests cho các lớp bảo mật mới: CSP header, optional API key, per-IP rate limit,
và redaction trên path chat (secrets không rò ra LLM/history)."""

from fastapi.testclient import TestClient

from zp_release_guard import security
from zp_release_guard.api import app

client = TestClient(app)


def test_csp_header_present():
    resp = client.get("/health")
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy")
    assert csp and "default-src 'self'" in csp
    assert "script-src 'self' https://cdn.jsdelivr.net" in csp
    assert "img-src 'self' data: blob:" in csp


def test_api_key_optional_then_enforced(monkeypatch):
    # Không set APP_API_KEY → mở (giữ tương thích local/test)
    resp = client.post("/chat", json={"message": "hi"}, headers={"X-Forwarded-For": "10.0.0.1"})
    assert resp.status_code == 200

    # Set APP_API_KEY → protected path đòi header khớp
    monkeypatch.setenv("APP_API_KEY", "s3cret")
    try:
        denied = client.post("/chat", json={"message": "hi"}, headers={"X-Forwarded-For": "10.0.0.2"})
        assert denied.status_code == 401
        ok = client.post(
            "/chat",
            json={"message": "hi"},
            headers={"X-API-Key": "s3cret", "X-Forwarded-For": "10.0.0.3"},
        )
        assert ok.status_code == 200
    finally:
        security._rate_hits.clear()


def test_rate_limit_returns_429():
    ip = "203.0.113.77"  # isolated bucket so other tests aren't affected
    limit = security._RATE_LIMIT_PER_MINUTE
    try:
        # Burn the bucket up to the limit
        for _ in range(limit):
            r = client.post("/chat", json={"message": "hi"}, headers={"X-Forwarded-For": ip})
            assert r.status_code == 200
        blocked = client.post("/chat", json={"message": "hi"}, headers={"X-Forwarded-For": ip})
        assert blocked.status_code == 429
        assert blocked.headers.get("Retry-After") == "60"
    finally:
        security._rate_hits.pop(ip, None)


def test_chat_path_redacts_secrets():
    from zp_release_guard.chat_engine import chat_history, generate_natural_chat_reply

    chat_id = 778899
    chat_history.pop(chat_id, None)
    secret = "mytestsecret123456"
    generate_natural_chat_reply(chat_id, f"check this token={secret} please")
    stored = " ".join(m["content"] for m in chat_history.get(chat_id, []))
    assert secret not in stored
    assert "<redacted" in stored
    chat_history.pop(chat_id, None)


def test_feedback_endpoint():
    ok = client.post("/feedback", json={"rating": "up", "chat_id": 5})
    assert ok.status_code == 200 and ok.json()["status"] == "ok"
    down = client.post("/feedback", json={"rating": "down", "note": "thiếu chi tiết"})
    assert down.status_code == 200
    # invalid rating rejected
    bad = client.post("/feedback", json={"rating": "meh"})
    assert bad.status_code == 422
