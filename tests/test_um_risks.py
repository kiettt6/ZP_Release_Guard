# Tests cho domain UM (User Management) học từ Confluence space ZTM:
# eKYC/DR rules, NFC/VNeID, PIN framework (ResetPinV2/TLSD), OTP, CE out-app.

from zp_release_guard.domains import detect_domains
from zp_release_guard.risks import detect_risks


def _titles(msg: str) -> list[str]:
    return [f.title for f in detect_risks(msg, ["general_release_change"], ["release_note"])]


# =============================================================================
# Risk rules
# =============================================================================

def test_reset_pin_tlsd_gating_rule():
    # ResetPinV2/TLSD: luồng được gate bằng risk check / RBA-MFA / KBA / owner flow
    title = "Reset PIN / balance liquidation flow change lacks risk, MFA, or KBA gating."
    msg = "Update resetpinv2 submit step to unlink bank accounts before update pin."
    assert title in _titles(msg)

    msg_mitigated = (
        "Update resetpinv2 submit step. Risk check and KBA gating unchanged, "
        "MFA challenge verified, pending request check still runs first."
    )
    assert title not in _titles(msg_mitigated)


def test_otp_antispam_rule():
    # Incident 2021-06-26: spam SMS OTP qua phone status + replay send_otp_token
    title = "OTP send endpoint change lacks anti-spam and abuse controls."
    msg = "Expose new send otp api for login by phone flow."
    assert title in _titles(msg)

    msg_mitigated = (
        "Expose new send otp api with rate limit per phone and risk engine "
        "checkpoint, captcha when flagged."
    )
    assert title not in _titles(msg_mitigated)


def test_upstream_strict_parsing_rule():
    # Incident 2021-10-13: Zalo Social API bỏ field birthday làm gãy login ZPI
    title = "Strict parsing of upstream profile/vendor response without lenient fallback."
    msg = "Parse response from zalo api get profile including birthday field for login."
    assert title in _titles(msg)

    msg_mitigated = (
        "Parse response from zalo api get profile. Birthday is an optional field "
        "with default value and lenient parsing."
    )
    assert title not in _titles(msg_mitigated)


def test_ekyc_dr_rule_blocking_rule():
    # PCFUM-11420: chặn OCR submit theo DR-031/DR-049 cần bypass + kill switch
    title = "eKYC OCR/DR-rule blocking change lacks bypass, kill switch, or unknown-code fallback."
    msg = "Block ocr submit when dr-031 or dr-049 mismatch_reasons returned."
    assert title in _titles(msg)

    msg_mitigated = (
        "Block ocr submit on dr-031 with three-strike bypass, a/b flag kill switch, "
        "and unknown reason code no-op fallback."
    )
    assert title not in _titles(msg_mitigated)


def test_decision_flow_enum_rule():
    # [URGENT] Worldcup dev note: enum UiDecisionFlow map thẳng sang điều hướng UI
    title = "Backend decision-flow enum change without client mapping test and default case."
    msg = "Add df_reason values to uidecisionflow for nfc verification flow."
    assert title in _titles(msg)

    msg_mitigated = (
        "Add df_reason values to uidecisionflow. Client has default case and "
        "enum mapping test for unknown enum values."
    )
    assert title not in _titles(msg_mitigated)


def test_ce_ticket_duplicate_rule():
    # CE out-app: phải pre-check ticket pending theo request_type trước khi tạo
    title = "CE/out-app ticket creation change lacks pending-ticket duplicate check."
    msg = "Allow user to create out-app ticket from TLSD screen via createticket."
    assert title in _titles(msg)

    msg_mitigated = (
        "Allow user to create out-app ticket. Searchticket runs check pending "
        "with request_type filter before creating."
    )
    assert title not in _titles(msg_mitigated)


def test_auth_gate_removal_rule():
    # Cụm phủ định trực tiếp ("bỏ bước KBA") phải trigger CRITICAL dù keyword
    # mitigation (kba) xuất hiện trong câu
    title = "An authentication or risk gate is being removed or weakened."
    msg = "Cập nhật reset pin v2, bỏ bước KBA để giảm friction cho user."
    assert title in _titles(msg)

    msg_mitigated = (
        "Cập nhật reset pin v2, bỏ bước KBA. Đã review security và được phê duyệt risk, "
        "có compensating control bằng face authen bắt buộc."
    )
    assert title not in _titles(msg_mitigated)


# =============================================================================
# Domain detection
# =============================================================================

def test_um_domain_detection():
    assert "user_management" in detect_domains("Update reset pin flow with KBA challenge")
    assert "user_management" in detect_domains("Thay đổi luồng thanh lý số dư và đổi mật khẩu")
    assert "user_management" in detect_domains("Deploy user-vneid and vneid-connector for consent callback")
    assert "user_management" in detect_domains("Smart OTP replaces SMS OTP in change pin")
    assert "user_management" in detect_domains("CE out-app ticket with flow_token for sim recycling")


def test_um_keywords_extend_kyc_domain():
    assert "kyc_account_status" in detect_domains("Integrate TrueID face authen with BCA verification")
    assert "kyc_account_status" in detect_domains("Xác thực sinh trắc học qua VNeID")


def test_um_domain_baseline_finding():
    findings = detect_risks(
        "Cập nhật luồng đăng nhập.",
        ["user_management"],
        ["release_note"],
    )
    assert any(f.category == "Domain impact" for f in findings)
