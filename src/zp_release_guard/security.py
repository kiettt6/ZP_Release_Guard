import os
import re
import threading
import time

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse


MAX_ANALYSIS_MESSAGE_CHARS = 50_000
MAX_HINT_CHARS = 160
MAX_REQUEST_BYTES = 256_000
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
UPLOAD_PATHS = frozenset({"/chat-upload"})

# Endpoints that call the (paid) LLM or run analysis — gated by optional API key
# and per-IP rate limiting so the service can't be abused or run up LLM cost.
PROTECTED_PATHS = frozenset({"/chat", "/chat-upload", "/analyze-freeform", "/invocations"})

# Content-Security-Policy: lock to same-origin except the CDNs the web UI loads
# (marked/dompurify via jsdelivr, Google Fonts). No inline scripts are used, so
# script-src omits 'unsafe-inline'. Self-hosting these would let us drop the CDNs.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

_RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
_RATE_WINDOW_SECONDS = 60.0
_rate_lock = threading.Lock()
_rate_hits: dict[str, list[float]] = {}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MARKDOWN_HEADING = re.compile(r"(?m)^\s{0,3}#{1,6}\s+")
_HTML_TAG = re.compile(r"<[^>\n]{1,120}>")


def clean_untrusted_text(text: str, *, max_chars: int) -> str:
    cleaned = _CONTROL_CHARS.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    cleaned = cleaned.strip()
    if len(cleaned) > max_chars:
        raise ValueError(f"Input exceeds maximum length of {max_chars} characters.")
    return cleaned


def clean_hint(text: str | None) -> str | None:
    if text is None:
        return None
    return clean_untrusted_text(str(text), max_chars=MAX_HINT_CHARS)


def validate_analysis_text(text: str) -> str:
    cleaned = clean_untrusted_text(text, max_chars=MAX_ANALYSIS_MESSAGE_CHARS)
    if not cleaned:
        raise ValueError("Input message is required.")
    return cleaned


def neutralize_markdown_injection(text: str) -> str:
    text = _HTML_TAG.sub("<redacted:html>", text)
    text = _MARKDOWN_HEADING.sub("heading: ", text)
    return text.replace("```", "`\u200b``").replace("|", "\\|")


async def enforce_request_size(request: Request, call_next) -> Response:
    # Starlette middlewares cannot reliably surface raised HTTPExceptions, so
    # return a JSONResponse directly when the body exceeds the limit.
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            size = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        limit = MAX_UPLOAD_BYTES if request.url.path in UPLOAD_PATHS else MAX_REQUEST_BYTES
        if size > limit:
            return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    return await call_next(request)


async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["Cache-Control"] = "no-store"
    return response


def _client_ip(request: Request) -> str:
    # Trust X-Forwarded-For only behind a known proxy; first hop is the client.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits.get(ip)
        if hits is None:
            hits = []
            _rate_hits[ip] = hits
        # prune outside the window
        cutoff = now - _RATE_WINDOW_SECONDS
        hits[:] = [t for t in hits if t > cutoff]
        if len(hits) >= _RATE_LIMIT_PER_MINUTE:
            return True
        hits.append(now)
        # opportunistic cleanup so the map doesn't grow unbounded
        if len(_rate_hits) > 10_000:
            for stale_ip in [k for k, v in _rate_hits.items() if not v or v[-1] < cutoff]:
                _rate_hits.pop(stale_ip, None)
    return False


async def enforce_access(request: Request, call_next) -> Response:
    """Optional API-key auth + per-IP rate limit on the LLM-calling endpoints.

    - If APP_API_KEY is set, protected paths require a matching `X-API-Key` header.
      Unset (default) keeps the service open for local/internal use and tests.
    - Per-IP rate limit (RATE_LIMIT_PER_MINUTE, default 120) caps abuse/cost.
    """
    if request.url.path in PROTECTED_PATHS:
        expected_key = os.getenv("APP_API_KEY")
        if expected_key:
            provided = request.headers.get("x-api-key", "")
            if provided != expected_key:
                return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key."})
        if _rate_limited(_client_ip(request)):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
                headers={"Retry-After": "60"},
            )
    return await call_next(request)
