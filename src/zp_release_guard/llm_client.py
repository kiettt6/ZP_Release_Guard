"""Centralized LLM client for all OpenAI-compatible calls (VNG MaaS by default).

Gom 3 chỗ gọi LLM (chat agent, rewrite report, OCR ảnh) về một nơi để:
- chọn model theo vai trò (LLM_MODEL_CHAT / _REWRITE / _OCR, fallback LLM_MODEL),
- retry/backoff cho lỗi tạm thời (timeout, 5xx, 429),
- logging có cấu trúc thay cho print(),
- một chokepoint dễ kiểm soát (timeout, header, base_url).

Không phụ thuộc thêm package: vẫn dùng `requests` như phần còn lại của repo.
"""

import logging
import os
import time

import requests

logger = logging.getLogger("zp_release_guard.llm")

DEFAULT_BASE_URL = "https://maas-llm-aiplatform-hcm.api.vngcloud.vn/v1"
DEFAULT_MODEL = "google/gemma-4-31b-it"

# Mỗi vai trò có thể cấu hình model riêng; fallback về LLM_MODEL rồi default.
# - chat:     follow-up Q&A nhanh, nhẹ (model nhỏ/nhanh, vd Gemma)
# - analysis: phân tích sâu tài liệu upload (model mạnh, vd DeepSeek Pro)
# - rewrite:  rewrite report (cosmetic)
# - ocr:      transcribe ảnh (cần model vision)
_ROLE_ENV = {
    "chat": "LLM_MODEL_CHAT",
    "analysis": "LLM_MODEL_ANALYSIS",
    "rewrite": "LLM_MODEL_REWRITE",
    "ocr": "LLM_MODEL_OCR",
}


def base_url() -> str:
    return os.getenv("LLM_BASE_URL", DEFAULT_BASE_URL)


def api_key() -> str | None:
    return os.getenv("LLM_API_KEY")


def is_configured() -> bool:
    """True khi có API key — dùng để fallback graceful khi LLM chưa cấu hình."""
    return bool(api_key())


def model_for(role: str) -> str:
    specific_env = _ROLE_ENV.get(role)
    specific = os.getenv(specific_env) if specific_env else None
    return specific or os.getenv("LLM_MODEL", DEFAULT_MODEL)


def chat_completion(
    messages: list[dict],
    *,
    role: str = "chat",
    temperature: float = 0.7,
    timeout: int = 30,
    max_retries: int = 2,
    max_tokens: int | None = None,
) -> str | None:
    """Gọi /chat/completions và trả về content (string) hoặc None nếu lỗi/chưa cấu hình.

    `messages` đi thẳng qua payload nên hỗ trợ cả multimodal (content là list cho OCR).
    `max_tokens` giới hạn độ dài output — đặt cao cho tác vụ cần output dài (vd sinh
    nhiều test case) để tránh server cắt ngắn câu trả lời (JSON đứt giữa chừng).
    Retry cho timeout/5xx/429; KHÔNG retry cho 4xx khác (lỗi request, retry vô ích).
    """
    key = api_key()
    if not key:
        return None

    url = f"{base_url().rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {"model": model_for(role), "messages": messages, "temperature": temperature}
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices") or []
            if not choices:
                logger.warning("LLM returned no choices (role=%s, model=%s)", role, payload["model"])
                return None
            content = (choices[0].get("message") or {}).get("content", "")
            return content.strip() or None
        except requests.RequestException as exc:
            last_exc = exc
            status = exc.response.status_code if exc.response is not None else None
            # 4xx (trừ 429) là lỗi request — retry không giúp gì.
            if status is not None and 400 <= status < 500 and status != 429:
                logger.warning("LLM client error %s (role=%s) — not retrying", status, role)
                break
            if attempt < max_retries:
                time.sleep(0.8 * (attempt + 1))

    logger.warning("LLM call failed after retries (role=%s): %s", role, last_exc)
    return None
