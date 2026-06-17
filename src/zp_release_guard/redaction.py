import re


SECRET_PATTERNS = [
    re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+([A-Za-z0-9._\-:/+=]{8,})"),
    re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-:/+=]{8,})"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|authorization|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9._\-:/+=]{8,})['\"]?"),
    re.compile(r"\b\d{9,}:[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\b[A-Za-z0-9_=-]{24,}\.[A-Za-z0-9_=-]{12,}\.[A-Za-z0-9_=-]{12,}\b"),
]

PII_PATTERNS = [
    re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"),
    re.compile(r"\b(?:\+?84|0)(?:3|5|7|8|9)\d{8}\b"),
    re.compile(r"(?i)\b(?:cccd|cmnd|citizen[_ -]?id|national[_ -]?id)\s*[:=]?\s*\d{9,12}\b"),
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
]


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_redact_secret_match, redacted)
    return redacted


def _redact_secret_match(match: re.Match[str]) -> str:
    if match.lastindex:
        secret_value = match.group(match.lastindex)
        return match.group(0).replace(secret_value, "<redacted:secret>")
    return "<redacted:secret>"


def redact_sensitive_data(text: str) -> str:
    redacted = redact_secrets(text)
    for pattern in PII_PATTERNS:
        redacted = pattern.sub(lambda m: "<redacted:pii>", redacted)
    return redacted


def evidence_snippet(text: str, limit: int = 220) -> str:
    from zp_release_guard.security import neutralize_markdown_injection

    normalized = " ".join(redact_sensitive_data(text).split())
    normalized = neutralize_markdown_injection(normalized)
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."
