from fastapi.testclient import TestClient

from zp_release_guard.api import app
from zp_release_guard.samples import SAMPLES


client = TestClient(app)


def test_health() -> None:
    # Test GET /health
    response_get = client.get("/health")
    assert response_get.status_code == 200
    assert response_get.json()["status"] == "ok"

    # Test POST /health
    response_post = client.post("/health")
    assert response_post.status_code == 200
    assert response_post.json()["status"] == "ok"


def test_analyze_freeform_api() -> None:
    response = client.post(
        "/analyze-freeform",
        json={"message": SAMPLES["refund"], "project_hint": "zalopay", "release_hint": "demo"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "Critical"
    assert body["recommendation"] == "No-Go"
    assert "## P0 Smoke Checklist" in body["markdown_report"]


def test_agentbase_invocation_endpoint() -> None:
    response = client.post(
        "/invocations",
        json={"message": SAMPLES["promo"], "project_hint": "zalopay", "release_hint": "agentbase"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] in {"High", "Critical"}
    assert "## QA Recommendation" in body["markdown_report"]


def test_agentbase_invocation_requires_message() -> None:
    response = client.post("/invocations", json={})

    assert response.status_code == 422


def test_api_rejects_extra_fields_and_large_payload() -> None:
    extra_response = client.post(
        "/analyze-freeform",
        json={"message": "refund retry timeout", "unexpected": "field"},
    )
    assert extra_response.status_code == 422

    large_response = client.post("/analyze-freeform", json={"message": "a" * 50_001})
    assert large_response.status_code == 422


def test_api_security_headers_are_set() -> None:
    response = client.get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_chat_endpoint_routes_casual_input_to_chat_reply() -> None:
    response = client.post("/chat", json={"message": "hello"})

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "chat"
    assert body["reply"]
    assert body["chat_id"] >= 1
    assert body["risk_level"] is None
    assert body["recommendation"] is None


def test_chat_endpoint_returns_report_for_release_content() -> None:
    response = client.post("/chat", json={"message": SAMPLES["refund"]})

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "report"
    assert body["risk_level"] == "Critical"
    assert body["recommendation"] == "No-Go"
    assert "## QA Review Summary" in body["reply"] or "## Tóm tắt QA" in body["reply"]
    assert body["chat_id"] >= 1


def test_chat_endpoint_preserves_chat_id_across_turns() -> None:
    first = client.post("/chat", json={"message": "hi"}).json()
    chat_id = first["chat_id"]

    second = client.post(
        "/chat",
        json={"message": "bạn có thể làm được gì", "chat_id": chat_id},
    )
    assert second.status_code == 200
    body = second.json()
    assert body["chat_id"] == chat_id


def test_chat_endpoint_rejects_empty_message() -> None:
    response = client.post("/chat", json={"message": ""})
    assert response.status_code == 422


def test_chat_endpoint_rejects_oversized_message() -> None:
    response = client.post("/chat", json={"message": "a" * 50_001})
    assert response.status_code == 422


def test_chat_endpoint_rejects_extra_fields() -> None:
    response = client.post("/chat", json={"message": "hi", "unexpected": "field"})
    assert response.status_code == 422


def test_web_ui_served_at_root() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "ZLP ReleaseGuard" in response.text
    # Welcome card content and core JS hooks should be present
    assert 'id="composer"' in response.text
    assert "/app.js" in response.text
    assert "/styles.css" in response.text


def test_chat_upload_with_text_file() -> None:
    payload = SAMPLES["refund"].encode("utf-8")
    response = client.post(
        "/chat-upload",
        files={"file": ("refund.txt", payload, "text/plain")},
        data={"message": ""},
    )

    assert response.status_code == 200
    body = response.json()
    # Uploads now run through the deterministic 11-section analyzer (same as the
    # typed-text path) so a file produces the full QA report with risk_level and
    # recommendation populated.
    assert body["kind"] == "report"
    assert body["file_kind"] == "text"
    assert body["file_name"] == "refund.txt"
    # endpoint strips trailing whitespace before measuring
    assert body["extracted_chars"] == len(payload.decode("utf-8").strip())
    assert body["risk_level"] is not None
    assert body["recommendation"] is not None
    assert body["reply"]


def test_chat_upload_image_uses_llm_transcription() -> None:
    # transcribe_image_with_llm returns a synthetic diff string under pytest
    response = client.post(
        "/chat-upload",
        files={"file": ("screenshot.png", b"\x89PNG fakebytes", "image/png")},
        data={"message": "phân tích giúp"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["file_kind"] == "image"
    # OCR'd content (a git diff here) is analyzed by the template engine → report.
    assert body["kind"] == "report"
    assert "diff --git" in body["extracted_text"]


def test_chat_upload_accepts_multiple_files() -> None:
    response = client.post(
        "/chat-upload",
        files=[
            ("files", ("a.txt", b"first refund note", "text/plain")),
            ("files", ("b.txt", b"second ledger note", "text/plain")),
        ],
        data={"message": "compare these"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "report"
    assert body["file_count"] == 2
    assert body["file_names"] == ["a.txt", "b.txt"]
    assert body["file_name"] == "2 attachments"
    assert body["file_kind"] == "text"
    assert "### File 1: a.txt (text)" in body["extracted_text"]
    assert "### File 2: b.txt (text)" in body["extracted_text"]


def test_chat_upload_rejects_too_many_files() -> None:
    response = client.post(
        "/chat-upload",
        files=[
            ("files", (f"f{i}.txt", b"x", "text/plain"))
            for i in range(6)
        ],
    )

    assert response.status_code == 413


def test_chat_upload_rejects_oversized_file() -> None:
    huge = b"a" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/chat-upload",
        files={"file": ("huge.txt", huge, "text/plain")},
    )

    assert response.status_code == 413


def test_chat_upload_rejects_unsupported_extension() -> None:
    response = client.post(
        "/chat-upload",
        files={"file": ("malware.exe", b"\x4d\x5a\x90\x00", "application/octet-stream")},
    )

    assert response.status_code == 415


def test_chat_upload_preserves_chat_id() -> None:
    first = client.post("/chat", json={"message": "hello"}).json()
    chat_id = first["chat_id"]

    response = client.post(
        "/chat-upload",
        files={"file": ("hint.txt", b"Refund retry partner timeout", "text/plain")},
        data={"chat_id": str(chat_id)},
    )
    assert response.status_code == 200
    assert response.json()["chat_id"] == chat_id


def test_web_ui_static_assets_served() -> None:
    css = client.get("/styles.css")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]

    js = client.get("/app.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    # Must call POST /chat for round-trip
    assert "/chat" in js.text
