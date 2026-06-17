from zp_release_guard.parser import detect_input_types
from zp_release_guard.language import clean_latex_symbols
from zp_release_guard.domains import detect_domains


def test_detects_diff_and_impact_doc() -> None:
    message = """Impact Analysis
Scope: refund only.
diff --git a/refund.py b/refund.py
@@ -1 +1 @@
"""
    assert detect_input_types(message) == ["git_diff", "impact_analysis_doc"]


def test_detects_prd_release_note_and_bugfix() -> None:
    assert "prd_text" in detect_input_types("PRD acceptance criteria for bank linking.")
    assert "release_note" in detect_input_types("Release Notes v1.2.3")
    assert "bugfix_summary" in detect_input_types("Bug fix root cause: callback timeout.")


def test_clean_latex_symbols() -> None:
    text = "Verify Case 1: User chưa KYC, chưa NFC $\\rightarrow$ Hệ thống"
    assert clean_latex_symbols(text) == "Verify Case 1: User chưa KYC, chưa NFC → Hệ thống"

    text2 = "User đã KYC $\\rightArrow$ flow NFC"
    assert clean_latex_symbols(text2) == "User đã KYC → flow NFC"

    text3 = "Compare x \\le y or a \\geq b"
    assert clean_latex_symbols(text3) == "Compare x ≤ y or a ≥ b"


def test_detect_domains_for_kyc_nfc_cccd() -> None:
    assert "kyc_account_status" in detect_domains("Chụp ảnh CCCD để định danh")
    assert "kyc_account_status" in detect_domains("Xác thực khuôn mặt bằng NFC chip")
    assert "kyc_account_status" in detect_domains("Thực hiện flow ekyc mới")

