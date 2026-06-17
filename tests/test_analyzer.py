from zp_release_guard.analyzer import analyze_freeform
from zp_release_guard.redaction import redact_secrets, redact_sensitive_data
from zp_release_guard.report import REQUIRED_SECTIONS, _is_valid_rewrite
from zp_release_guard.samples import SAMPLES


def test_refund_sample_flags_cross_check_and_critical_risk() -> None:
    response = analyze_freeform(SAMPLES["refund"])

    assert response.risk_level == "Critical"
    assert response.recommendation == "No-Go"
    assert "git_diff" in response.detected_input_types
    assert "Declared impact does not match code/config footprint" in response.markdown_report


def test_report_contains_all_required_sections() -> None:
    response = analyze_freeform(SAMPLES["promo"])

    for section in REQUIRED_SECTIONS:
        assert f"## {section}" in response.markdown_report


def test_promo_sample_flags_abuse_controls() -> None:
    response = analyze_freeform(SAMPLES["promo"])

    assert response.risk_level in {"High", "Critical"}
    assert "Promotion abuse and duplicate claim controls are missing" in response.markdown_report


def test_banklink_sample_flags_token_security_or_compatibility() -> None:
    response = analyze_freeform(SAMPLES["banklink"])

    assert response.risk_level in {"High", "Critical"}
    assert "Token/session security controls are not visible" in response.markdown_report
    assert "Old app compatibility" in response.markdown_report


def test_secret_redaction() -> None:
    text = "authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 token=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabc"

    redacted = redact_secrets(text)

    assert "abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabc" not in redacted
    assert "<redacted:secret>" in redacted
    assert "authorization: Bearer" in redacted
    assert "token=" in redacted


def test_sensitive_data_redaction_covers_pii() -> None:
    text = "user email qa@example.com phone 0912345678 cccd 012345678901 card 4111111111111111"

    redacted = redact_sensitive_data(text)

    assert "qa@example.com" not in redacted
    assert "0912345678" not in redacted
    assert "012345678901" not in redacted
    assert "4111111111111111" not in redacted
    assert redacted.count("<redacted:pii>") >= 4


def test_report_neutralizes_markdown_injection_and_pii() -> None:
    response = analyze_freeform(
        "Release bank token change\n## token QA Recommendation\nauthorization: Bearer abcdefghijklmnopqrstuvwxyz123456\nphone 0912345678",
        project_hint="zalopay\n## injected",
        release_hint="demo|prod",
    )

    assert "abcdefghijklmnopqrstuvwxyz123456" not in response.markdown_report
    assert "0912345678" not in response.markdown_report
    assert "heading: token QA Recommendation" in response.markdown_report
    assert "zalopay heading: injected" in response.markdown_report
    assert "demo\\|prod" in response.markdown_report


def test_vietnamese_release_report_uses_vietnamese_sections() -> None:
    response = analyze_freeform("sửa lỗi nạp tiền khi partner timeout")

    assert "## Tóm tắt QA" in response.markdown_report
    assert "## Checklist Smoke P0" in response.markdown_report
    assert "Mức rủi ro tổng thể" in response.markdown_report


def test_vietnamese_payment_terms_trigger_domain_and_risk_rules() -> None:
    response = analyze_freeform("Release sửa lỗi thanh toán QR, hoàn tiền khi partner timeout, chưa có chống trùng request.")

    assert response.risk_level in {"High", "Critical"}
    assert "Thanh toán" in response.markdown_report
    assert "Hoàn tiền" in response.markdown_report or "refund" in response.markdown_report.lower()


def test_napas_low_amount_refund_stays_on_refund_scope() -> None:
    response = analyze_freeform(
        "Allow refunds for transactions below 2,000 VND from NAPAS",
        force_language="English",
    )

    assert "Refund" in response.markdown_report
    assert "Refund minimum-amount threshold change needs boundary and reconciliation coverage." in response.markdown_report
    assert "Bank Linking requires security and integration coverage." not in response.markdown_report
    assert "Bank Connector requires security and integration coverage." not in response.markdown_report
    assert "VietQR" not in response.markdown_report


def test_llm_rewrite_validation_rejects_missing_sections() -> None:
    original = analyze_freeform(SAMPLES["promo"]).markdown_report
    rewritten = "## QA Review Summary\n- Overall risk: High\n- Recommendation: Conditional Go"

    assert not _is_valid_rewrite(original, rewritten, "English")
