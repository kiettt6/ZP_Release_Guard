from zp_release_guard.chat_engine import handle_command


def test_sample_refund_command_returns_report() -> None:
    result = handle_command("/sample refund")

    assert "## QA Review Summary" in result
    assert "No-Go" in result


def test_analyze_command_requires_payload() -> None:
    assert handle_command("/analyze") == "Paste release content after /analyze."


def test_raw_text_analyzed_directly() -> None:
    result = handle_command("Refund retry flow with partner timeout")
    assert "## QA Review Summary" in result
    assert "No-Go" in result


def test_short_vietnamese_release_text_is_analyzed_directly() -> None:
    result = handle_command("sửa lỗi nạp tiền")

    assert "## Tóm tắt QA" in result
    assert "Mức rủi ro tổng thể" in result


def test_casual_chat_greeting_returns_natural_response() -> None:
    result = handle_command("hi")
    assert "How can I help you today?" in result

    result_vn = handle_command("xin chào")
    assert "Tôi có thể hỗ trợ gì cho bạn hôm nay?" in result_vn


def test_capability_question_covers_all_zalopay_flows() -> None:
    result = handle_command("ban có thể làm được gì nào")

    assert "toàn bộ các flow trong ZaloPay" in result
    assert "KYC/eKYC" in result
    assert "Merchant" in result
    assert "Settlement/Reconciliation" in result
    assert "Mobile app" in result


def test_transcribe_image_mock() -> None:
    from zp_release_guard.chat_engine import transcribe_image_with_llm

    result = transcribe_image_with_llm(b"fake_bytes", "image/jpeg")
    assert "diff --git" in result


def test_report_helpers() -> None:
    from zp_release_guard.chat_engine import is_impact_analysis_report, markdown_report_filename

    english_report = "## QA Review Summary\n- Overall risk: High\n- Recommendation: Conditional Go\n- Finding count: Critical=0, High=1\n\n## DEV Impact Template Coverage\n### 1. Overview\n- Scope of Change: Payment, Bank Linking\n\n## Confirmed Impact\n- Payment\n\n## Potential Missing Impact\n- Missing idempotency\n\n## P0 Smoke Checklist\n- Validate retry"
    vietnamese_report = "## Tóm tắt QA\n- Mức rủi ro tổng thể: Critical\n- Khuyến nghị: No-Go\n- Số lượng finding: Critical=1\n\n## Coverage theo template Impact Analysis của DEV\n### 1. Overview / Tổng quan\n- Scope of Change: Nạp tiền, Liên kết ngân hàng\n\n## Ảnh hưởng đã xác nhận\n- Nạp tiền\n\n## Ảnh hưởng có thể bị bỏ sót\n- Thiếu idempotency\n\n## Checklist Smoke P0\n- Validate retry"

    assert is_impact_analysis_report(english_report)
    assert is_impact_analysis_report(vietnamese_report)
    assert not is_impact_analysis_report("Hello")
    assert markdown_report_filename(english_report) == "zp-release-guard-payment-bank-linking-payment-impact-report.md"
    assert markdown_report_filename(vietnamese_report) == "zp-release-guard-nap-tien-lien-ket-ngan-hang-nap-tien-impact-report-vi.md"
    assert markdown_report_filename("## QA Review Summary\n") == "zp-release-guard-general-release-impact-report.md"


def test_chat_history_is_populated() -> None:
    from zp_release_guard.chat_engine import chat_history

    chat_history.clear()

    handle_command("hello", chat_id=123)
    assert 123 in chat_history
    assert len(chat_history[123]) == 2
    assert chat_history[123][0]["role"] == "user"
    assert chat_history[123][0]["content"] == "hello"
    assert chat_history[123][1]["role"] == "assistant"

    handle_command("Refund retry flow with partner timeout", chat_id=123)
    assert len(chat_history[123]) == 4
    assert "Refund retry flow with partner timeout" in chat_history[123][2]["content"]
    assert "QA" in chat_history[123][3]["content"] or "Review" in chat_history[123][3]["content"] or "No-Go" in chat_history[123][3]["content"]


def test_extract_text_from_pdf_mock(monkeypatch) -> None:
    from zp_release_guard.chat_engine import extract_text_from_pdf

    class MockPage:
        def extract_text(self):
            return "Hello world from PDF"

    class MockReader:
        def __init__(self, stream):
            self.pages = [MockPage()]

    import pypdf
    monkeypatch.setattr(pypdf, "PdfReader", MockReader)

    result = extract_text_from_pdf(b"dummy pdf bytes")
    assert result == "Hello world from PDF"


def test_last_report_context_populated_after_analysis() -> None:
    from zp_release_guard.chat_engine import last_report_context, chat_history

    last_report_context.clear()
    chat_history.clear()

    handle_command("Refund retry flow with partner timeout", chat_id=9001)

    assert 9001 in last_report_context
    ctx = last_report_context[9001]
    assert "Risk:" in ctx
    assert "Recommendation:" in ctx


def test_handle_command_forwards_replied_message_to_chat_reply(monkeypatch) -> None:
    from zp_release_guard import chat_engine

    captured: dict = {}

    def fake_chat_reply(chat_id, message, replied_assistant_message=None, force_language=None):
        captured["chat_id"] = chat_id
        captured["message"] = message
        captured["replied_assistant_message"] = replied_assistant_message
        return "chat reply"

    monkeypatch.setattr(chat_engine, "generate_natural_chat_reply", fake_chat_reply)

    result = chat_engine.handle_command(
        "focus vào phần này",
        chat_id=42,
        replied_assistant_message="1. Phân tích rủi ro luồng thanh toán...",
    )

    assert result == "chat reply"
    assert captured["replied_assistant_message"] == "1. Phân tích rủi ro luồng thanh toán..."
    assert captured["message"] == "focus vào phần này"


def test_extract_text_from_docx() -> None:
    from zp_release_guard.chat_engine import extract_text_from_docx
    import docx
    import io

    doc = docx.Document()
    doc.add_paragraph("Hello world from DOCX")
    f = io.BytesIO()
    doc.save(f)
    docx_bytes = f.getvalue()

    result = extract_text_from_docx(docx_bytes)
    assert result == "Hello world from DOCX"


def test_capability_question_only_for_short_messages():
    from zp_release_guard.chat_engine import _is_capability_question, generate_natural_chat_reply

    assert _is_capability_question("bạn làm được gì") is True
    assert _is_capability_question("help") is True

    long_doc = (
        "Tôi vừa upload file 'PLAN.md'. Đây là nội dung trích xuất:\n"
        "Hướng dẫn triển khai release v2.8: thêm cột status vào bảng wallet_balance, "
        "cập nhật luồng refund, rollback plan chưa có. " * 5
        + "\n\nđây là gì"
    )
    assert _is_capability_question(long_doc) is False

    reply = generate_natural_chat_reply(0, long_doc)
    assert "không chỉ riêng Payment" not in reply
    assert "Review Impact Analysis" not in reply


def test_strip_chat_preamble():
    from zp_release_guard.chat_engine import _strip_chat_preamble

    doc = (
        "Chào bạn, mình đã nhận được nội dung techspec cho MBBank. "
        "Dưới đây là phân tích:\n\n"
        "## Tóm tắt\n- Tính năng xem số dư MBBank."
    )
    out = _strip_chat_preamble(doc)
    assert out.startswith("## Tóm tắt")
    assert "Chào bạn" not in out

    clean = "## Tóm tắt\n- abc\n\n## Rủi ro\n- def"
    assert _strip_chat_preamble(clean) == clean

    real = "Tính năng này thay đổi luồng balance.\n\n## Rủi ro\n- x"
    assert _strip_chat_preamble(real) == real


def test_clarification_not_triggered_for_vietnamese_with_context():
    from zp_release_guard.chat_engine import _needs_clarification

    detailed_vi = "Cập nhật luồng hoàn tiền refund, gộp cancel và refund, chạm bảng ledger_journal."
    assert _needs_clarification(detailed_vi) is False

    assert _needs_clarification("sửa lỗi nạp tiền") is True
    assert _needs_clarification("update payment") is True


def test_assistant_memory_line_is_natural_not_dump():
    from zp_release_guard.chat_engine import _assistant_memory_line

    vi = "## Tóm tắt QA\n- Mức rủi ro tổng thể: Critical\n- Khuyến nghị: No-Go\n- Số lượng finding: Critical=1"
    en = "## QA Review Summary\n- Overall risk: High\n- Recommendation: Conditional Go\n- Finding count: High=6"

    line_vi = _assistant_memory_line(vi)
    assert "Last QA analysis" not in line_vi
    assert "Findings:" not in line_vi
    assert "Critical" in line_vi and "No-Go" in line_vi

    line_en = _assistant_memory_line(en)
    assert "Last QA analysis" not in line_en
    assert "High" in line_en and "Conditional Go" in line_en


def test_language_switch_rerenders_full_report():
    from zp_release_guard.chat_engine import handle_command, last_analyzed_input

    cid = 555001
    last_analyzed_input.pop(cid, None)

    r1 = handle_command("Refund flow with partner timeout, ledger_journal and refund_request impact.", chat_id=cid)
    assert "## QA Review Summary" in r1

    r2 = handle_command("tiếng việt", chat_id=cid)
    assert "## Tóm tắt QA" in r2
    assert "## QA Review Summary" not in r2

    r3 = handle_command("in english", chat_id=cid)
    assert "## QA Review Summary" in r3
    last_analyzed_input.pop(cid, None)


def test_force_language_overrides_message_detection():
    from zp_release_guard.chat_engine import generate_natural_chat_reply, handle_command, last_analyzed_input

    cid = 555002
    last_analyzed_input.pop(cid, None)

    report = handle_command(
        "Sửa lỗi refund flow với partner timeout, ảnh hưởng ledger_journal và refund_request.",
        chat_id=cid,
        force_language="English",
    )
    assert "## QA Review Summary" in report

    reply = generate_natural_chat_reply(0, "xin chào", force_language="English")
    assert reply.startswith("Hello!")

    last_analyzed_input.pop(cid, None)


def test_detect_language_switch():
    from zp_release_guard.chat_engine import _detect_language_switch

    assert _detect_language_switch("tiếng việt") == "Vietnamese"
    assert _detect_language_switch("in english") == "English"
    assert _detect_language_switch("chuyển qua tiếng anh") == "English"
    assert _detect_language_switch("giải thích finding này") is None
    assert _detect_language_switch("a" * 60) is None


def test_is_testcase_request_detection():
    from zp_release_guard.chat_engine import _is_testcase_request

    assert _is_testcase_request("viết test case cho refund flow")
    assert _is_testcase_request("liệt kê test case P0")
    assert _is_testcase_request("write test cases for this change")
    assert _is_testcase_request("test cases")
    # Not a request to produce test cases
    assert not _is_testcase_request("tại sao finding này critical?")
    assert not _is_testcase_request("giải thích rủi ro double refund")


def test_testcase_request_returns_structured_block():
    # In pytest mode the LLM is short-circuited; a test-case request must still
    # come back as a parseable ```testcases JSON block (cards + xlsx in the UI).
    result = handle_command("viết test case cho refund VietQR NAPAS", force_language="Vietnamese")
    assert "```testcases" in result

    import json
    import re

    payload = re.search(r"```testcases\s*([\s\S]*?)```", result).group(1)
    data = json.loads(payload)
    assert isinstance(data["groups"], list) and data["groups"]
    assert data["groups"][0]["cases"][0]["id"].startswith("TC-")


def test_testcase_translate_continuation_keeps_structured_block():
    # Regression: after test cases, a bare "tiếng anh" / "in english" must regenerate
    # the ```testcases block (cards + xlsx), not fall back to plain prose.
    from zp_release_guard.chat_engine import (
        _is_testcase_continuation,
        last_was_testcases,
    )

    assert _is_testcase_continuation("tiếng anh")
    assert _is_testcase_continuation("in english")
    assert _is_testcase_continuation("viết thêm vài case nữa")
    assert not _is_testcase_continuation("tại sao TC-NEG-01 lại quan trọng?")

    cid = 778899
    first = handle_command("viết test case cho refund flow", chat_id=cid)
    assert "```testcases" in first
    assert last_was_testcases.get(cid) is True

    # Translate request — must still come back as a structured block.
    translated = handle_command("tiếng anh", chat_id=cid, force_language="English")
    assert "```testcases" in translated

    last_was_testcases.pop(cid, None)


def test_help_to_list_test_cases_is_not_capability_reply():
    # Regression: "pls help to list test cases" contains the word "help" but is a real
    # test-case request — it must NOT return the canned capability intro.
    from zp_release_guard.chat_engine import _is_capability_question

    assert not _is_capability_question("pls help to list test cases for this section")
    assert not _is_capability_question("help me review this diff")
    assert _is_capability_question("help")          # bare help still works
    assert _is_capability_question("bạn làm được gì")

    result = handle_command("pls help to list test cases for this section", chat_id=445566)
    assert "```testcases" in result
    assert "I am ZLP ReleaseGuard" not in result
