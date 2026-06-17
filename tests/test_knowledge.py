# Tests cho knowledge base chọn lọc theo câu hỏi (nguồn: Confluence ZTM + PD)

from zp_release_guard.knowledge import KNOWLEDGE_BASE, render_knowledge_prompt, select_knowledge


def _ids(message: str, max_blocks: int = 4) -> list[str]:
    return [block["id"] for block in select_knowledge(message, max_blocks=max_blocks)]


def test_kyc_limit_question_vietnamese():
    # Câu hỏi hạn mức bằng tiếng Việt có dấu phải chọn đúng block KYC limits
    ids = _ids("Hạn mức chuyển tiền của tài khoản K1 là bao nhiêu?")
    assert "kyc_tiers_limits" in ids


def test_voucher_question():
    ids = _ids("User báo voucher biến mất sau khi thanh toán fail thì xử lý sao?")
    assert "promotion_cashback_voucher" in ids


def test_error_code_question():
    ids = _ids("Topup bị lỗi -8003 thì tiền có được hoàn không?")
    assert "transfer_topup_errors" in ids


def test_dr_rule_question():
    ids = _ids("Tại sao eKYC bị auto reject với lỗi trùng chân dung?")
    assert "ekyc_dr_rules" in ids


def test_retry_semantics_question():
    ids = _ids("Order FAILED rồi thì retry với cùng idempotency key được không?")
    assert "retry_idempotency_semantics" in ids


def test_tt40_force_nfc_question():
    ids = _ids("Khi nào user bị force NFC khi chuyển tiền theo TT40?")
    assert "tt40_compliance" in ids


def test_specific_error_code_lookup():
    # Mã lỗi trong range được liệt kê đủ trong keywords
    assert "kyc_tiers_limits" in _ids("lỗi -1342 nghĩa là gì")
    # Mã lỗi chỉ xuất hiện trong content vẫn được dò ra qua fallback
    assert "transfer_topup_errors" in _ids("giao dịch trả về -8350 thì sao")


def test_card_processing_block():
    ids = _ids("MTI 0220 advice cho Pismo clearing xử lý thế nào")
    assert "card_processing" in ids


def test_ekyc_nfc_reason_code_block():
    ids = _ids("reason code 22 BCA maintenance trong user-ekyc-nfc là gì")
    assert "ekyc_nfc_reason_codes" in ids


def test_agreement_pay_lazada_code():
    ids = _ids("Lazada trả về -7240 khi querybalance nghĩa là gì")
    assert "agreement_pay_partners" in ids


def test_bank_connector_block():
    assert "bank_connector" in _ids("bc-api trả về -5000 escrow account nghĩa là gì")
    assert "bank_connector" in _ids("RBA callback của bank bị xử lý trùng, idempotency thế nào")
    assert "bank_connector" in _ids("thứ tự deploy shared-lib receiver bc-api ra sao")


def test_bank_connector_content_facts():
    from zp_release_guard.knowledge import KNOWLEDGE_BASE

    bc = next(b for b in KNOWLEDGE_BASE if b["id"] == "bank_connector")["content"]
    assert "-5000" in bc and "escrow" in bc.lower()
    assert "-9205" in bc
    assert "shared-lib" in bc and "convertTransEntity" in bc
    assert "sf2TransactionIdentifier" in bc


def test_deep_content_has_specific_facts():
    # Nội dung sâu phải chứa các fact cụ thể đã trích từ Confluence
    from zp_release_guard.knowledge import KNOWLEDGE_BASE

    by_id = {b["id"]: b["content"] for b in KNOWLEDGE_BASE}
    assert "exactly once" in by_id["card_processing"].lower()
    assert "30 minutes" in by_id["promotion_cashback_voucher"].lower()
    assert "flow_token" in by_id["um_account_flows"]
    assert "fund loss" in by_id["settlement_reconciliation"].lower()
    assert "guarantee account" in by_id["bank_maintenance_monitoring"].lower()


def test_max_blocks_honored():
    # Câu hỏi chạm nhiều domain vẫn chỉ trả về tối đa max_blocks
    msg = "ekyc voucher cashback transfer settlement retry maintenance tiktok otp incident"
    assert len(select_knowledge(msg, max_blocks=3)) <= 3


def test_unrelated_text_returns_nothing():
    assert select_knowledge("hôm nay trời đẹp quá nhỉ") == []
    assert render_knowledge_prompt("hello how are you") == ""


def test_render_prompt_contains_title_and_content():
    prompt = render_knowledge_prompt("Hạn mức K3 là bao nhiêu?")
    assert "KYC tiers" in prompt
    assert "100M" in prompt


def test_knowledge_base_structure():
    # Mỗi block phải đủ field và keyword đã được normalize (không còn dấu)
    from zp_release_guard.language import normalize_vietnamese_text

    ids = set()
    for block in KNOWLEDGE_BASE:
        assert block["id"] not in ids, f"duplicate id {block['id']}"
        ids.add(block["id"])
        assert block["title"] and block["content"] and block["keywords"]
        for keyword in block["keywords"]:
            assert keyword == keyword.lower()
            assert keyword == normalize_vietnamese_text(keyword), (
                f"keyword '{keyword}' in {block['id']} chưa strip dấu"
            )
