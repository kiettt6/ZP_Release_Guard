import re
import sys
import unicodedata

import logging

from zp_release_guard import llm_client
from zp_release_guard.analyzer import analyze_freeform
from zp_release_guard.knowledge import render_knowledge_prompt
from zp_release_guard.language import clean_latex_symbols, has_vietnamese_release_signal, normalize_vietnamese_text, response_language_for
from zp_release_guard.redaction import redact_secrets
from zp_release_guard.samples import get_sample

logger = logging.getLogger("zp_release_guard.chat")

REPORT_MARKERS = (
    "## QA Review Summary",
    "## Tóm tắt QA",
)

import threading

# In-process conversation state. NOTE: single-instance only — across multiple API
# replicas a follow-up may land on a different process and lose context. For a
# multi-replica deployment move these to Redis/a shared TTL store.
_STATE_LOCK = threading.Lock()
MAX_TRACKED_CHATS = 5_000  # bound memory: evict oldest chats beyond this many

chat_history: dict[int, list[dict[str, str]]] = {}
pending_clarification: dict[int, str] = {}  # chat_id -> original message waiting for more context
last_report_context: dict[int, str] = {}  # chat_id -> compact findings summary for follow-up LLM context
last_analyzed_input: dict[int, str] = {}  # chat_id -> raw input of the last report, for language re-render
last_was_testcases: dict[int, bool] = {}  # chat_id -> True if the last reply was a ```testcases block


def _evict_old_chats() -> None:
    """Drop the oldest chat_ids (insertion order) once we exceed the cap, so the
    in-process maps cannot grow unbounded with one entry per user."""
    with _STATE_LOCK:
        overflow = len(chat_history) - MAX_TRACKED_CHATS
        if overflow <= 0:
            return
        for stale_id in list(chat_history.keys())[:overflow]:
            chat_history.pop(stale_id, None)
            pending_clarification.pop(stale_id, None)
            last_report_context.pop(stale_id, None)
            last_analyzed_input.pop(stale_id, None)
            last_was_testcases.pop(stale_id, None)


def _detect_language_switch(text: str) -> str | None:
    """Return 'Vietnamese'/'English' when a short message is essentially a request to
    switch the report language (e.g. 'tiếng việt', 'in english'), else None."""
    t = normalize_vietnamese_text(text.lower()).strip(" .!?,")
    if not t or len(t) > 40:
        return None
    en = any(k in t for k in ["tieng anh", "in english", "english", "sang en", "qua tieng anh"])
    vi = any(k in t for k in ["tieng viet", "in vietnamese", "vietnamese", "sang vn", "qua tieng viet"])
    if t in {"en"}:
        en = True
    if t in {"vn", "tv", "vi"}:
        vi = True
    if en and not vi:
        return "English"
    if vi and not en:
        return "Vietnamese"
    return None


def is_impact_analysis_report(text: str) -> bool:
    return any(marker in text for marker in REPORT_MARKERS)


def markdown_report_filename(text: str) -> str:
    slug = _report_feature_slug(text)
    language_suffix = "-vi" if "## Tóm tắt QA" in text else ""
    return f"zp-release-guard-{slug}-impact-report{language_suffix}.md"


def _report_feature_slug(report: str) -> str:
    candidates = []
    for section_name in ("## Coverage theo template Impact Analysis của DEV", "## DEV Impact Template Coverage"):
        for line in _section_lines(report, section_name):
            if line.startswith("- Scope of Change:"):
                candidates.append(line.removeprefix("- Scope of Change:").strip())
    for section_name in ("## Ảnh hưởng đã xác nhận", "## Confirmed Impact"):
        candidates.extend(_first_bullets(_section_lines(report, section_name), 3))

    raw_name = " ".join(item for item in candidates if item and "Không phát hiện" not in item and "None detected" not in item)
    slug = _slugify_filename(raw_name)
    return slug or "general-release"


def _slugify_filename(text: str, max_length: int = 70) -> str:
    normalized = unicodedata.normalize("NFD", text)
    ascii_text = "".join(char for char in normalized if unicodedata.category(char) != "Mn")
    ascii_text = ascii_text.replace("đ", "d").replace("Đ", "D").lower()
    ascii_text = re.sub(r"[^a-z0-9]+", "-", ascii_text)
    ascii_text = re.sub(r"-{2,}", "-", ascii_text).strip("-")
    if len(ascii_text) <= max_length:
        return ascii_text
    return ascii_text[:max_length].rstrip("-")


def _section_lines(report: str, heading: str) -> list[str]:
    lines = report.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == heading:
            start = index + 1
            break
    if start is None:
        return []

    section: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        if line.strip():
            section.append(line.strip())
    return section


def _field_value(lines: list[str], label: str) -> str | None:
    prefix = f"- {label}:"
    for line in lines:
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None


def _first_bullets(lines: list[str], limit: int) -> list[str]:
    bullets = []
    for line in lines:
        if line.startswith("- "):
            bullets.append(line.removeprefix("- ").strip())
        if len(bullets) >= limit:
            break
    return bullets


def _compact_report_context(report: str) -> str:
    """Build a concise findings summary for injecting into follow-up LLM system prompt."""
    is_vi = "## Tóm tắt QA" in report
    if is_vi:
        summary_lines = _section_lines(report, "## Tóm tắt QA")
        matrix_lines = _section_lines(report, "## Ma trận rủi ro")
        risk = _field_value(summary_lines, "Mức rủi ro tổng thể") or "N/A"
        rec = _field_value(summary_lines, "Khuyến nghị") or "N/A"
        count = _field_value(summary_lines, "Số lượng finding") or ""
    else:
        summary_lines = _section_lines(report, "## QA Review Summary")
        matrix_lines = _section_lines(report, "## Risk Matrix")
        risk = _field_value(summary_lines, "Overall risk") or "N/A"
        rec = _field_value(summary_lines, "Recommendation") or "N/A"
        count = _field_value(summary_lines, "Finding count") or ""
    finding_rows = [
        line for line in matrix_lines
        if line.startswith("|") and "---" not in line
        and "Severity" not in line and "Mức độ" not in line
    ]
    parts = [f"Last QA analysis — Risk: {risk} | Recommendation: {rec}{' | ' + count if count else ''}"]
    if finding_rows:
        parts.append("Findings:")
        for row in finding_rows[:8]:
            cols = [c.strip() for c in row.strip("|").split("|")]
            if len(cols) >= 2:
                parts.append(f"  - [{cols[1]}] {cols[0]}")
    return "\n".join(parts)


def _assistant_memory_line(report: str) -> str:
    """A SHORT, natural sentence to store as the assistant's chat-history turn after
    a report. The raw machine summary (_compact_report_context) is kept separately as
    system-prompt reference data — storing it as the assistant's 'voice' makes the LLM
    echo that robotic format on follow-ups instead of answering conversationally."""
    is_vi = "## Tóm tắt QA" in report
    if is_vi:
        s = _section_lines(report, "## Tóm tắt QA")
        risk = _field_value(s, "Mức rủi ro tổng thể") or "N/A"
        rec = _field_value(s, "Khuyến nghị") or "N/A"
        return (
            f"Mình đã phân tích và gửi báo cáo QA chi tiết (mức rủi ro {risk}, khuyến nghị {rec}). "
            "Bạn cứ hỏi mình giải thích bất kỳ finding, checklist hay rủi ro nào trong báo cáo nhé."
        )
    s = _section_lines(report, "## QA Review Summary")
    risk = _field_value(s, "Overall risk") or "N/A"
    rec = _field_value(s, "Recommendation") or "N/A"
    return (
        f"I analyzed it and shared a detailed QA report (risk {risk}, recommendation {rec}). "
        "Ask me to explain any finding, checklist item, or risk in the report."
    )


def is_casual_chat(text: str) -> bool:
    cleaned = text.lower().strip().strip("?.!,")
    if has_vietnamese_release_signal(cleaned):
        return False

    # Câu hỏi follow-up về QA report — không phải casual dù ngắn
    followup_signals = {
        # Tiếng Việt
        "tại sao", "giải thích", "ý nghĩa", "nghĩa là gì", "cụ thể hơn",
        "test gì", "kiểm tra gì", "nên làm gì", "làm sao", "như thế nào",
        "finding", "risk", "critical", "p0", "p1", "checklist",
        "tại sao critical", "tại sao high", "tại sao medium",
        "mình cần", "cần test", "cần check", "cần làm",
        "test case", "viết thêm", "thêm test", "bổ sung", "chi tiết hơn",
        "viết lại", "liệt kê", "danh sách", "gợi ý thêm", "ví dụ",
        # Tiếng Anh
        "why", "explain", "what does", "what is", "how to",
        "what should", "what to test", "what to check",
        "clarify", "elaborate", "more detail", "write more", "add more",
        "list", "give me", "show me", "example",
    }
    if any(signal in cleaned for signal in followup_signals):
        return False

    casual_phrases = {
        "hi", "hello", "xin chào", "xin chao", "chào", "chao", "hey", "test",
        "ping", "help", "cứu", "alo", "hola", "bonjour", "greetings", "yo",
        "bạn là ai", "who are you", "what can you do", "hướng dẫn", "how to use"
    }
    if cleaned in casual_phrases:
        return True

    if len(cleaned) < 35:
        fintech_keywords = {
            "diff", "git", "refund", "ledger", "db", "api", "voucher", "cashback",
            "promo", "pay", "bank", "token", "kyc", "card", "schema", "fix", "bug",
            "hotfix", "release", "impact", "change", "prd", "requirement", "criteria",
            # Thêm từ khóa ZaloPay thực tế
            "transid", "settlement", "recon", "idempotent", "callback", "napas",
            "wallet", "balance", "migration", "rollback", "batch", "worker",
        }
        if not any(kw in cleaned for kw in fintech_keywords):
            return True

    return False


def _is_capability_question(text: str) -> bool:
    cleaned = text.lower().strip().strip("?.!,")
    # Capability questions are short ("help", "bạn làm được gì"). Anything long is a
    # real query or an uploaded/pasted document — never treat that as a capability
    # question, otherwise a doc containing "hướng dẫn" etc. wrongly triggers the
    # canned intro instead of being analyzed.
    if len(cleaned) > 60:
        return False
    # A concrete task ("help to list/review/write…") is a real request, not a
    # "what can you do?" question — even though it may contain the word "help".
    normalized = normalize_vietnamese_text(cleaned)
    task_verbs = (
        "list", "review", "analyze", "analyse", "check", "write", "generate", "create",
        "suggest", "explain", "test case", "viet", "liet ke", "phan tich", "kiem tra",
        "danh gia", "giai thich", "de xuat", "tao",
    )
    if any(verb in normalized for verb in task_verbs):
        return False
    capability_phrases = {
        "help",
        "hướng dẫn",
        "huong dan",
        "how to use",
        "what can you do",
        "bạn có thể làm được gì",
        "ban có thể làm được gì",
        "ban co the lam duoc gi",
        "bạn làm được gì",
        "ban làm được gì",
        "ban lam duoc gi",
        "có thể làm gì",
        "co the lam gi",
    }
    return any(phrase in cleaned for phrase in capability_phrases)


def _is_testcase_request(text: str) -> bool:
    """True when the user is asking the assistant to write/list test cases — so we
    emit a structured ```testcases JSON block the web UI renders as cards + xlsx."""
    t = normalize_vietnamese_text(text.lower())
    # Must mention test cases / scenarios explicitly.
    has_tc = any(kw in t for kw in (
        "test case", "testcase", "test-case", "test scenario", "test scenarios",
        "kich ban test", "kich ban kiem thu", "ca kiem thu", "bo test", "tc-",
    ))
    if not has_tc:
        return False
    # And an intent to produce/list them (write, list, give, suggest, create…).
    wants = any(kw in t for kw in (
        "viet", "liet ke", "tao", "lap", "soan", "de xuat", "bo sung", "them",
        "danh sach", "list", "write", "generate", "create", "give", "suggest",
        "draft", "build", "design", "cho toi", "show",
    ))
    # A bare "test case" / "test cases" message is also a request.
    bare = t.strip(" .!?,") in {"test case", "test cases", "testcase", "testcases"}
    return wants or bare


def _is_testcase_continuation(text: str) -> bool:
    """True for short follow-ups that should keep producing test cases when the
    PREVIOUS reply was already test cases — e.g. 'tiếng anh' (translate), 'viết thêm',
    'more', 'chi tiết hơn'. Without this, a translate/continue message has no
    test-case keyword so the structured ```testcases block (cards + xlsx) is lost."""
    if _detect_language_switch(text):
        return True
    t = normalize_vietnamese_text(text.lower())
    if len(t) > 60:
        return False  # long messages are likely new content, not a continuation
    # A question / explanation request is NOT a continuation — the user wants an
    # answer about the existing cases, not a fresh batch.
    if any(q in t for q in ("tai sao", "vi sao", "why", "giai thich", "explain", "la gi", "nghia la")):
        return False
    keywords = (
        "them ", "bo sung", "viet them", "viet lai", "tiep", "tiep tuc", "chi tiet hon",
        "more", "continue", "rewrite", "redo", "expand", "nua",
        "in english", "in vietnamese", "tieng anh", "tieng viet",
    )
    return any(k in t for k in keywords)


# Strong, schema-locked instruction appended to the system prompt when the user
# asks for test cases. The web UI looks for the ```testcases fenced block and
# renders it as cards + an xlsx download button.
_TESTCASE_PROMPT = (
    "\n\nThe user is asking for TEST CASES. In addition to a brief one-line intro, you MUST output the test cases "
    "as a single fenced code block tagged `testcases` containing ONLY valid JSON (no comments, no trailing commas). "
    "Use this exact schema:\n"
    "```testcases\n"
    "{\n"
    '  "title": "<short title of what is being tested>",\n'
    '  "groups": [\n'
    "    {\n"
    '      "name": "<GROUP NAME — e.g. HAPPY PATH, NEGATIVE, EDGE/BOUNDARY, SECURITY>",\n'
    '      "type": "positive | negative | edge",\n'
    '      "cases": [\n'
    "        {\n"
    '          "id": "TC-HP-01",\n'
    '          "title": "<concise scenario name>",\n'
    '          "precondition": "<setup / điều kiện>",\n'
    '          "steps": "1. ...\\n2. ...",\n'
    '          "expected": "<expected result / kết quả mong đợi>",\n'
    '          "result": "PASS | FAIL expected",\n'
    '          "note": "<optional caveat / câu hỏi cần confirm, or empty string>"\n'
    "        }\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}\n"
    "```\n"
    "Rules:\n"
    "- Be COMPREHENSIVE, not minimal. A real feature has many scenarios — aim for AT LEAST 12-20 cases for a "
    "non-trivial feature (more if the scope is large). Do NOT stop after 2-3 cases. It is better to over-cover.\n"
    "- Systematically work through EVERY relevant category below and add cases for each that applies to the change:\n"
    "  1. Happy path — main success flow + meaningful variants (different amounts, channels, partners, user states).\n"
    "  2. Boundary / equivalence — min, max, just-below, just-above, zero, empty, very large, limits & caps.\n"
    "  3. Negative / validation — invalid input, missing fields, wrong status, unauthorized, rejected by business rule.\n"
    "  4. Idempotency / duplicate — same order_id / app_trans_id / request replay must not double-process.\n"
    "  5. Concurrency / race — simultaneous requests, double-click, parallel callbacks on the same record.\n"
    "  6. Timeout / retry — partner/Napas timeout then retry/late callback; ensure no double credit/debit.\n"
    "  7. Partial failure / rollback / compensation — step fails midway; state and ledger stay consistent.\n"
    "  8. Data integrity — ledger balanced (debit=credit), available_balance vs total_balance, reconciliation T+1.\n"
    "  9. Security / authz / fraud — permission checks, tampering, abuse/anti-spam, PII not leaked to logs.\n"
    "  10. Compatibility — old app version, backward-compatible API/schema, feature flag on/off.\n"
    "  11. Observability — correct error codes, alerts/metrics/logs emitted for failure paths.\n"
    "- Group the cases (HAPPY PATH, BOUNDARY/EDGE, NEGATIVE, IDEMPOTENCY/CONCURRENCY, SECURITY, COMPATIBILITY, …) and "
    "  give EACH group several cases — not one token case per group.\n"
    "- Make every case realistic and ZaloPay-specific: reference real amounts, error codes, partners (Napas/Visa/banks), "
    "  tables (transactions, ledger_journal, wallet_balance, refund_request) and fields from the actual change.\n"
    "- Use stable sequential ids per group: TC-HP-01.. (happy), TC-EDGE-01.. (boundary/edge), TC-NEG-01.. (negative), "
    "  TC-IDEM-01.. / TC-CONC-01.. (idempotency/concurrency), TC-SEC-01.. (security), TC-COMPAT-01.. (compatibility).\n"
    "- `result` is PASS for positive cases and 'FAIL expected' for negative/rejected cases.\n"
    "- Write field values in the response language. Output ONLY the JSON inside the single `testcases` fence — "
    "do NOT wrap it in another code fence and do NOT add prose after the block."
)


def _synthetic_testcases_block(language: str) -> str:
    """Deterministic ```testcases block for pytest (LLM is short-circuited there)."""
    intro = "Dưới đây là các test case đề xuất:" if language == "Vietnamese" else "Here are the suggested test cases:"
    return (
        intro + "\n\n```testcases\n"
        '{"title": "Refund VietQR NAPAS", "groups": [\n'
        '  {"name": "HAPPY PATH", "type": "positive", "cases": [\n'
        '    {"id": "TC-HP-01", "title": "Refund 1 VND", "precondition": "GD SUCCESS, amount=1 VND",'
        ' "steps": "1. Tạo GD\\n2. Gọi API refund", "expected": "Refund thành công", "result": "PASS", "note": ""}\n'
        '  ]},\n'
        '  {"name": "NEGATIVE", "type": "negative", "cases": [\n'
        '    {"id": "TC-NEG-01", "title": "Refund > 2000 VND bị chặn", "precondition": "amount=2001 VND",'
        ' "steps": "1. Gọi API refund", "expected": "REFUND_NOT_ALLOWED", "result": "FAIL expected", "note": ""}\n'
        '  ]}\n'
        ']}\n```'
    )


def _capability_reply(language: str) -> str:
    if language == "Vietnamese":
        return (
            "Tôi là ZLP ReleaseGuard, trợ lý QA review release cho toàn bộ các flow trong ZaloPay.\n\n"
            "Tôi có thể hỗ trợ:\n"
            "1. Review Impact Analysis, PRD, release note, Git diff hoặc bugfix summary.\n"
            "2. Phát hiện rủi ro trên các flow: Wallet, Payment, Refund, Top-up, Transfer, KYC/eKYC, Voucher/Promotion, Cashback/Reward, Merchant, Settlement/Reconciliation, Bank Connector, Tap2Pay, PayLater/Installment, Agreement Pay, Notification, Mobile app và back-office/ops jobs.\n"
            "3. Soi các điểm P0/P1: idempotency, double-processing, ledger balance, data integrity, rollback/compensation, backward compatibility, API contract, security/PII, fraud/abuse, performance và monitoring.\n"
            "4. Sinh QA report gồm risk level, recommendation Go/Conditional Go/No-Go, P0 smoke checklist, P1/P2 regression pack và câu hỏi cần dev xác nhận.\n\n"
            "Bạn chỉ cần gửi ticket/impact doc/diff/release note, tôi sẽ phân tích theo scope thực tế của flow đó."
        )
    return (
        "I am ZLP ReleaseGuard, a QA release review assistant for all ZaloPay flows.\n\n"
        "I can help with:\n"
        "1. Reviewing Impact Analysis docs, PRDs, release notes, Git diffs, or bugfix summaries.\n"
        "2. Detecting risks across Wallet, Payment, Refund, Top-up, Transfer, KYC/eKYC, Voucher/Promotion, Cashback/Reward, Merchant, Settlement/Reconciliation, Bank Connector, Tap2Pay, PayLater/Installment, Agreement Pay, Notification, Mobile app, and back-office/ops jobs.\n"
        "3. Checking P0/P1 concerns: idempotency, double-processing, ledger balance, data integrity, rollback/compensation, backward compatibility, API contracts, security/PII, fraud/abuse, performance, and monitoring.\n"
        "4. Producing a QA report with risk level, Go/Conditional Go/No-Go recommendation, P0 smoke checklist, P1/P2 regression pack, and questions for dev.\n\n"
        "Send a ticket, impact doc, diff, or release note and I will analyze it against the actual flow scope."
    )


def generate_natural_chat_reply(
    chat_id: int,
    message: str,
    replied_assistant_message: str | None = None,
    structured: bool = False,
    force_language: str | None = None,
) -> str:
    if chat_id:
        _evict_old_chats()
    # Redact secrets at the LLM boundary so nothing sensitive reaches the external
    # LLM or gets stored in chat_history (the templated analyze path redacts too).
    message = redact_secrets(message)
    if replied_assistant_message:
        replied_assistant_message = redact_secrets(replied_assistant_message)
    # A short "tiếng anh" / "in english" is a language-switch request — honor it as the
    # response language even though the message itself is written in another language.
    response_language = force_language or _detect_language_switch(message) or response_language_for(message)
    # A bare 'tiếng anh' / 'viết thêm' carries no test-case keyword, so also treat it
    # as a test-case request when the previous reply WAS test cases — otherwise the
    # structured ```testcases block (cards + xlsx) is lost on translate/continue.
    wants_testcases = _is_testcase_request(message) or (
        bool(chat_id and last_was_testcases.get(chat_id)) and _is_testcase_continuation(message)
    )
    # A real request (e.g. "pls help to list test cases") must not be hijacked by the
    # capability reply just because it contains the word "help".
    if _is_capability_question(message) and not wants_testcases:
        reply = _capability_reply(response_language)
        if chat_id:
            history = chat_history.setdefault(chat_id, [])
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply})
            last_was_testcases[chat_id] = False
        return reply

    if "pytest" in sys.modules:
        if wants_testcases:
            reply = _synthetic_testcases_block(response_language)
        elif response_language == "Vietnamese":
            reply = "Xin chào! Tôi là ZLP ReleaseGuard, trợ lý QA của bạn. Tôi có thể hỗ trợ gì cho bạn hôm nay?"
        else:
            reply = "Hello! I am ZLP ReleaseGuard, your QA assistant. How can I help you today?"
        if chat_id:
            history = chat_history.setdefault(chat_id, [])
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply})
            last_was_testcases[chat_id] = "```testcases" in reply
        return reply

    if not llm_client.is_configured():
        if response_language == "Vietnamese":
            return "Tính năng chat chưa được kích hoạt (chưa cấu hình LLM_API_KEY). Bạn vẫn có thể gửi impact analysis, diff, PRD hoặc release note để phân tích rủi ro."
        return "Chat is not enabled (LLM_API_KEY not configured). You can still send an impact analysis, diff, PRD, or release note for risk analysis."

    system_prompt = (
        "You are ZLP ReleaseGuard, an intelligent QA release-impact agent for all ZaloPay product, platform, mobile, partner-integration, and operations flows.\n"
        "Do not describe yourself as only specialized in payment integrity. Payment integrity is one critical focus, but your scope covers the full ZaloPay ecosystem.\n"
        "Do not reply like a simple automated assistant. Interact as a knowledgeable, helpful QA colleague.\n"
        "Write in natural, flowing sentences like a human teammate. NEVER answer with a machine-style data dump "
        "(e.g. 'Last QA analysis — Risk: ... | Recommendation: ... Findings: [High] ...') and never paste the raw "
        "report or reference data back verbatim. Explain in your own words and quote only the specific items the user asks about.\n"
        "If the user asks for the analysis in another language (e.g. 'tiếng anh', 'in English', 'tiếng việt'), "
        "rewrite the relevant findings naturally in that language — do not just echo the previous summary.\n"
        f"Respond in {response_language}.\n"
        "Do not introduce yourself unless the user explicitly asks or sends a greeting like 'hi', 'hello', '/start'.\n"
        "If the user asks a follow-up question about the QA analysis (e.g. 'why Critical?', 'explain this finding', 'what should I test first?'), "
        "use the analysis context provided at the end of this prompt to give a specific, actionable answer.\n"
        + (
            # Structured mode (file uploads → downloadable report): clean Markdown, no chit-chat.
            "Output a well-structured GitHub-flavored Markdown document: use `##`/`###` headings, `-` bullet lists, "
            "`**bold**` for key terms, and Markdown tables where useful (e.g. a risk matrix).\n"
            "Begin DIRECTLY with the analysis. Do NOT open with a greeting or acknowledgement such as "
            "'Chào bạn', 'mình đã nhận được', 'Dưới đây là...', 'Hi', 'Sure' — no preamble, no sign-off.\n"
            "Recommended sections: ## Tóm tắt, ## Rủi ro chính (với reference tới function/table/flow/field cụ thể), "
            "## Checklist test P0, ## Câu hỏi cần dev xác nhận.\n"
            if structured else
            "Do not use double asterisks (**), bold markdown, or markdown formatting. Output plain text only.\n"
        )

        # ZaloPay domain knowledge — giúp LLM trả lời đúng context
        + "\nZaloPay domain knowledge you must apply when answering questions:\n"
        "- Core flows: wallet balance, payment (QR, deeplink, merchant POS), refund, top-up, P2P transfer, cashback, voucher redemption, KYC/eKYC, bank linking, card tokenization, merchant onboarding, settlement/reconciliation, notification, mobile app compatibility, back-office operations, batch jobs, partner callbacks, Tap2Pay, PayLater/Installment, and Agreement Pay.\n"
        "- Idempotency: order_id is the standard key. Duplicate requests with same order_id must NOT re-process.\n"
        "- Critical tables: transactions, ledger_journal, settlement_batch, wallet_balance, refund_request.\n"
        "- Wallet rule: available_balance = total_balance - hold_balance (must update atomically).\n"
        "- Partners: Napas (domestic), Visa/Mastercard (international), major VN banks (VCB, TCB, MB, ACB).\n"
        "- Settlement: T+0 intraday with Napas, T+1 end-of-day batch with banks. Zero-tolerance mismatch.\n"
        "- Common failure patterns: duplicate Napas callback, partner timeout causing retry loop, "
        "stale sequence generator causing duplicate TransID, partial refund using wrong amount.\n"
        "- Mobile: Android/iOS app may stay mixed-version for weeks after release. "
        "API changes need backward compatibility or feature flag.\n"
        "- Compliance: SBV regulations for money movement, PCI-DSS for card data, "
        "eKYC data (CCCD/NFC) is PII and must not appear in logs.\n"
        "- User Management (UM): login, onboarding, PIN framework (change/reset PIN 'MKTT', KBA, MFA/RBA), OTP & smart OTP, "
        "TLSD (balance liquidation), CE out-app tickets (one-time flow_token), eKYC with DR rules (DR-031/DR-049 OCR blocking), "
        "NFC chip CCCD, VNeID integration, vendors TrueID/JTH/BCA. Reset-PIN and TLSD are risk-gated flows — "
        "any change there needs risk/MFA/KBA verification; OTP send paths need anti-spam (rate limit, risk engine, captcha).\n"

        # Hướng dẫn xử lý follow-up về QA report
        "\nWhen the user asks follow-up questions about a QA report (e.g. 'why Critical?', 'explain this finding', 'what should I test first?'):\n"
        "- Reference the specific findings, risk level, and checklist items from the report in conversation history.\n"
        "- Explain WHY each finding is risky using ZaloPay context above, not generic QA theory.\n"
        "- Prioritize P0 items and explain the blast radius in terms of customer funds or partner SLA.\n"
        "- If asked what to test, give 2-3 concrete, specific test cases based on the actual change described.\n"
    )

    if chat_id:
        report_ctx = last_report_context.get(chat_id)
        if report_ctx:
            system_prompt += (
                "\n\n---\nREFERENCE DATA — the most recent QA analysis you produced (machine-generated summary). "
                "Use it to answer accurately, but treat it ONLY as background data: NEVER copy or restate it verbatim, "
                "never reply with a 'Last QA analysis — Risk: ... Findings: ...' style dump. Always answer in your own "
                "natural words as a helpful colleague, quoting only the specific finding the user asks about.\n"
                f"{report_ctx}\n---"
            )

    if replied_assistant_message:
        system_prompt += (
            "\n\nThe user is replying directly to this previous assistant message. "
            "When they use deictic references — 'phần này', 'cái này', 'this', 'this item', 'item 2', "
            "'focus vào đây', 'giải thích cái này', 'test gì cho phần này', etc. — they are pointing at "
            "specific content inside this exact message:\n"
            "---START OF MESSAGE THE USER REPLIED TO---\n"
            f"{replied_assistant_message}\n"
            "---END OF MESSAGE THE USER REPLIED TO---\n"
            "Answer based on that exact content. Do NOT ask the user to clarify which part they mean "
            "unless that message itself is genuinely ambiguous."
        )

    # Chọn block kiến thức Confluence (ZTM/PD) liên quan đến câu hỏi; với follow-up
    # ngắn ("tại sao critical?") thì dựa thêm vào context report gần nhất.
    knowledge_basis = message
    if chat_id and last_report_context.get(chat_id):
        knowledge_basis = f"{message}\n{last_report_context[chat_id]}"
    system_prompt += render_knowledge_prompt(knowledge_basis)

    if wants_testcases:
        system_prompt += _TESTCASE_PROMPT

    # Build messages: system + existing history + new user turn.
    # NOTE: append user message to history only AFTER a successful LLM response to
    # prevent orphan turns (user msg with no assistant reply) that confuse the LLM on
    # the next call.
    if chat_id:
        history = chat_history.setdefault(chat_id, [])
        messages = [{"role": "system", "content": system_prompt}] + list(history) + [{"role": "user", "content": message}]
    else:
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": message}]

    # Structured reports (file uploads) are deep analysis → use the stronger 'analysis'
    # model (DeepSeek Pro) with more time. Casual follow-up chat → fast 'chat' model
    # (e.g. Gemma) to keep latency low.
    if structured:
        content = llm_client.chat_completion(messages, role="analysis", temperature=0.4, timeout=90, max_retries=1)
    elif wants_testcases:
        # Test cases must come back as valid JSON → stronger model + low temperature.
        # Comprehensive coverage means a long reply, so raise max_tokens and the timeout
        # so the JSON is not truncated mid-array (which would break card rendering).
        content = llm_client.chat_completion(
            messages, role="analysis", temperature=0.2, timeout=120, max_retries=1, max_tokens=8000
        )
    else:
        content = llm_client.chat_completion(messages, role="chat", temperature=0.7, timeout=30)
    if content is None:
        if response_language == "Vietnamese":
            return "Xin lỗi, tôi không thể xử lý yêu cầu lúc này (LLM không phản hồi). Vui lòng thử lại sau."
        return "Sorry, I could not process your request right now (LLM did not respond). Please try again."

    if structured:
        reply = clean_latex_symbols(_strip_chat_preamble(content))
    else:
        reply = clean_latex_symbols(content.replace("**", ""))

    # Persist the exchange to history only on success
    if chat_id:
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": reply})
        last_was_testcases[chat_id] = "```testcases" in reply
        if len(history) > 10:
            chat_history[chat_id] = history[-10:]
    return reply


_PREAMBLE_RE = re.compile(
    r"^\s*(chào bạn|chào|xin chào|hi|hello|hey|sure|chắc chắn|được(?: thôi)?|"
    r"mình đã nhận|tôi đã nhận|mình đã xem|cảm ơn bạn đã)\b",
    re.IGNORECASE,
)


def _strip_chat_preamble(text: str) -> str:
    """Remove a leading conversational/acknowledgement paragraph (e.g. 'Chào bạn,
    mình đã nhận được... Dưới đây là phân tích:') so a structured report starts at
    the first real heading/content."""
    blocks = text.lstrip().split("\n\n", 1)
    if len(blocks) == 2:
        first = blocks[0].strip()
        # Only strip a short opener that is NOT already a markdown heading/list.
        if (
            not first.startswith("#")
            and not first.startswith("-")
            and not first.startswith("|")
            and len(first) < 320
            and (_PREAMBLE_RE.search(first) or first.rstrip().endswith(":"))
        ):
            return blocks[1].lstrip()
    return text.strip()


def is_release_content(text: str) -> bool:
    cleaned = text.lower()
    if has_vietnamese_release_signal(cleaned):
        return True

    if "diff --git" in text or "+++" in text or "@@" in text:
        return True

    from zp_release_guard.parser import INPUT_PATTERNS
    for name, patterns in INPUT_PATTERNS.items():
        if any(pattern.search(text) for pattern in patterns):
            return True

    release_words = {
        "commit", "deploy", "rollback", "hotfix", "changelog", "release note",
        "prd", "acceptance criteria", "impact analysis", "bug fix", "refactor"
    }
    if any(word in cleaned for word in release_words):
        return True

    risk_terms = {
        "refund", "ledger", "balance", "idempot", "retry", "timeout", "callback",
        "token", "kyc", "settlement", "cashback", "voucher", "schema",
        "migration", "compatibility"
    }
    if any(term in cleaned for term in risk_terms):
        return True

    return False


def _needs_clarification(message: str) -> bool:
    """True when the message has payment signals but is too vague for a quality QA report."""
    stripped = message.strip()

    # Already long or structured enough — don't interrupt
    if len(stripped) >= 200:
        return False
    if any(sig in stripped for sig in (
        "diff --git", "+++", "## QA", "## Tóm tắt", "Impact Analysis",
        "Release Note", "Acceptance Criteria", "Out of scope",
    )):
        return False

    # Diacritic-normalized so Vietnamese-with-diacritics ("luồng", "ảnh hưởng",
    # "cập nhật") matches the (un-accented) keyword lists — otherwise the assistant
    # wrongly nags for clarification on perfectly detailed Vietnamese input.
    lowered = normalize_vietnamese_text(stripped.lower())

    # Has a payment/release signal worth asking about
    has_payment_signal = any(kw in lowered for kw in [
        "fix", "change", "update", "refund", "payment", "deploy", "release",
        "migration", "api", "schema", "config", "feature", "hotfix", "rollout",
        "sua", "thay doi", "cap nhat", "phat hanh", "trien khai", "sua loi",
    ])

    # But missing scope / service context
    has_context = any(kw in lowered for kw in [
        "scope", "in scope", "out of scope", "service", "component", "module",
        "affect", "impact", "flow", "pham vi", "anh huong", "dich vu", "luong",
        "table", "endpoint", "function", "worker", "job", "class", "bang ", "field",
    ])

    return has_payment_signal and not has_context


def _clarification_question(language: str) -> str:
    """Return a targeted question asking for missing context."""
    if language == "Vietnamese":
        return (
            "Để tạo QA report và checklist chính xác, tôi cần thêm thông tin:\n\n"
            "1. Service/component nào bị thay đổi?\n"
            "   (ví dụ: payment-service, refund-worker, wallet-api)\n"
            "2. Loại thay đổi:\n"
            "   bugfix / feature mới / config update / migration DB / refactor\n"
            "3. Phạm vi ảnh hưởng:\n"
            "   - In scope: luồng/flow nào bị tác động?\n"
            "   - Out of scope: luồng nào KHÔNG bị tác động?\n\n"
            "Trả lời để tôi phân tích chi tiết hơn.\n"
            "Hoặc gõ phân tích ngay để tiếp tục với thông tin hiện có."
        )
    return (
        "To generate an accurate QA report and checklist, I need a bit more context:\n\n"
        "1. Which service/component is being changed?\n"
        "   (e.g. payment-service, refund-worker, wallet-api)\n"
        "2. Type of change:\n"
        "   bugfix / new feature / config update / DB migration / refactor\n"
        "3. Scope of impact:\n"
        "   - In scope: which flows are affected?\n"
        "   - Out of scope: which flows are NOT affected?\n\n"
        "Reply with the details for a more targeted analysis.\n"
        "Or type analyze now to proceed with the current input."
    )


def _is_new_document(text: str) -> bool:
    """True when text looks like a new document to analyze rather than a follow-up question.
    A new document is typically long, multi-line, and structurally rich (diff, impact doc, PRD…).
    Short single-sentence messages — even those containing fintech keywords — are follow-up questions."""
    stripped = text.strip()
    # Git diff is always a new document regardless of length
    if "diff --git" in stripped or ("+++" in stripped and "---" in stripped and "@@" in stripped):
        return True
    # Multi-line and substantial — likely a pasted document
    if "\n" in stripped and len(stripped) > 400:
        return True
    return False


_SKIP_CLARIFICATION = {
    "analyze now", "skip", "no more info", "just analyze",
    "phân tích ngay", "cứ phân tích", "analyze luôn", "phan tich ngay",
}


def analyze_and_track(
    text: str,
    chat_id: int = 0,
    force_language: str | None = None,
    release_hint: str | None = None,
    user_label: str | None = None,
) -> str:
    """Run the deterministic 11-section analyzer and record per-chat follow-up state.

    Shared by the typed-text path (handle_command) and the file-upload path so both
    produce the full QA report and support the same follow-up questions afterwards."""
    if chat_id:
        _evict_old_chats()
    report = analyze_freeform(text, release_hint=release_hint, force_language=force_language).markdown_report
    if chat_id:
        compact = _compact_report_context(report)
        last_report_context[chat_id] = compact
        history = chat_history.setdefault(chat_id, [])
        stored = user_label or (text if len(text) < 2000 else text[:2000] + "...")
        history.append({"role": "user", "content": stored})
        history.append({"role": "assistant", "content": _assistant_memory_line(report)})
        last_analyzed_input[chat_id] = text
        last_was_testcases[chat_id] = False
        if len(history) > 10:
            chat_history[chat_id] = history[-10:]
    return report


def handle_command(
    text: str,
    chat_id: int = 0,
    replied_assistant_message: str | None = None,
    force_language: str | None = None,
) -> str:
    if chat_id:
        _evict_old_chats()
    text = clean_latex_symbols(text)
    stripped = text.strip()
    if not stripped:
        lang = force_language or response_language_for(text)
        return "Vui lòng nhập nội dung để phân tích." if lang == "Vietnamese" else "Please send some text to analyze."

    # --- User is replying to a pending clarification question ---
    if chat_id and chat_id in pending_clarification:
        original = pending_clarification.pop(chat_id)
        if stripped.lower().strip("?.!,") in _SKIP_CLARIFICATION:
            combined = original
        else:
            combined = f"{original}\n\nAdditional context from developer:\n{stripped}"
        report = analyze_freeform(combined, force_language=force_language).markdown_report
        if chat_id:
            compact = _compact_report_context(report)
            last_report_context[chat_id] = compact
            history = chat_history.setdefault(chat_id, [])
            history.append({"role": "user", "content": f"Additional context: {stripped}"})
            history.append({"role": "assistant", "content": _assistant_memory_line(report)})
            last_analyzed_input[chat_id] = combined
            last_was_testcases[chat_id] = False
            if len(history) > 10:
                chat_history[chat_id] = history[-10:]
        return report

    # --- User asks to switch the report language ("tiếng việt" / "in english") ---
    # Re-render the SAME report in that language (deterministic) instead of an LLM
    # summary, so the full structured report is translated, not paraphrased.
    # Skip when the last reply was test cases — those must be regenerated as a
    # ```testcases block in the chat path (handled below), not re-rendered as a report.
    if chat_id and chat_id in last_analyzed_input and not last_was_testcases.get(chat_id):
        switch_lang = _detect_language_switch(stripped)
        if switch_lang:
            report = analyze_freeform(last_analyzed_input[chat_id], force_language=switch_lang).markdown_report
            compact = _compact_report_context(report)
            last_report_context[chat_id] = compact
            history = chat_history.setdefault(chat_id, [])
            history.append({"role": "user", "content": stripped})
            history.append({"role": "assistant", "content": _assistant_memory_line(report)})
            last_was_testcases[chat_id] = False
            if len(history) > 10:
                chat_history[chat_id] = history[-10:]
            return report

    if stripped.startswith("/"):
        if stripped == "/start":
            return (
                "ZLP ReleaseGuard\n"
                "Send any release content (impact doc, diff, PRD, release note, or bugfix summary) directly to analyze.\n"
                "Or use: /sample refund|promo|banklink."
            )
        if stripped.startswith("/sample "):
            sample_name = stripped.removeprefix("/sample ").strip()
            sample = get_sample(sample_name)
            if not sample:
                return "Unknown sample. Available: refund, promo, banklink."
            report = analyze_freeform(
                sample,
                release_hint=f"sample-{sample_name}",
                force_language=force_language,
            ).markdown_report
            if chat_id:
                compact = _compact_report_context(report)
                last_report_context[chat_id] = compact
                history = chat_history.setdefault(chat_id, [])
                history.append({"role": "user", "content": f"Requested sample analysis for: {sample_name}"})
                history.append({"role": "assistant", "content": _assistant_memory_line(report)})
                last_analyzed_input[chat_id] = sample
                last_was_testcases[chat_id] = False
                if len(history) > 10:
                    chat_history[chat_id] = history[-10:]
            return report
        if stripped.startswith("/analyze "):
            payload = stripped.removeprefix("/analyze ").strip()
            if not payload:
                return "Paste release content after /analyze."
            report = analyze_freeform(payload, force_language=force_language).markdown_report
            if chat_id:
                compact = _compact_report_context(report)
                last_report_context[chat_id] = compact
                history = chat_history.setdefault(chat_id, [])
                stored_payload = payload if len(payload) < 2000 else payload[:2000] + "..."
                history.append({"role": "user", "content": f"Analyze release: {stored_payload}"})
                history.append({"role": "assistant", "content": _assistant_memory_line(report)})
                last_analyzed_input[chat_id] = payload
                last_was_testcases[chat_id] = False
                if len(history) > 10:
                    chat_history[chat_id] = history[-10:]
            return report
        if stripped == "/analyze":
            return "Paste release content after /analyze."
        return "Unsupported command. Use /start, /sample refund|promo|banklink, or simply send the text directly to analyze."

    # When an active conversation context exists, treat any message that is NOT clearly
    # a new document (long + multi-line + structured content) as a follow-up question.
    # This handles cases like "viết thêm test case", "tại sao callback retry gây double
    # payment?", "explain the Critical finding" etc. — which may contain release keywords
    # but are clearly questions/requests about the previous analysis, not new docs to analyze.
    has_context = bool(chat_id and (last_report_context.get(chat_id) or chat_history.get(chat_id)))
    is_new_doc = _is_new_document(stripped)
    # A test-case request always goes to the chat path so it returns a structured
    # ```testcases block (cards + xlsx) rather than a full QA report.
    if (has_context and not is_new_doc) or is_casual_chat(stripped) or not is_release_content(stripped) or _is_testcase_request(stripped):
        return generate_natural_chat_reply(
            chat_id,
            stripped,
            replied_assistant_message=replied_assistant_message,
            force_language=force_language,
        )

    # --- Ask for more context when input is too vague for a quality report ---
    # Skip clarification if there is already conversation context — the user expects
    # a follow-up answer, not another round of questions.
    if chat_id and not has_context and _needs_clarification(stripped):
        language = force_language or response_language_for(stripped)
        question = _clarification_question(language)
        pending_clarification[chat_id] = stripped
        history = chat_history.setdefault(chat_id, [])
        history.append({"role": "user", "content": stripped})
        history.append({"role": "assistant", "content": question})
        if len(history) > 10:
            chat_history[chat_id] = history[-10:]
        return question

    # Analyze release content directly
    report = analyze_freeform(stripped, force_language=force_language).markdown_report
    if chat_id:
        compact = _compact_report_context(report)
        last_report_context[chat_id] = compact
        history = chat_history.setdefault(chat_id, [])
        stored_text = stripped if len(stripped) < 2000 else stripped[:2000] + "..."
        history.append({"role": "user", "content": f"Release content for analysis:\n{stored_text}"})
        history.append({"role": "assistant", "content": _assistant_memory_line(report)})
        last_analyzed_input[chat_id] = stripped
        last_was_testcases[chat_id] = False
        if len(history) > 10:
            chat_history[chat_id] = history[-10:]
    return report


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    import io
    from pypdf import PdfReader
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        return text.strip()
    except Exception as e:
        logger.warning("Error parsing PDF: %s", e)
        raise e


def extract_text_from_docx(docx_bytes: bytes) -> str:
    import io
    import docx
    try:
        doc = docx.Document(io.BytesIO(docx_bytes))
        text = ""
        for para in doc.paragraphs:
            if para.text:
                text += para.text + "\n"
        return text.strip()
    except Exception as e:
        logger.warning("Error parsing DOCX: %s", e)
        raise e


def transcribe_image_with_llm(image_bytes: bytes, mime_type: str) -> str:
    import base64

    if "pytest" in sys.modules:
        return "Synthetic transcribed text from image: diff --git a/src/zp_release_guard/api.py b/src/zp_release_guard/api.py"

    if not llm_client.is_configured():
        return "Error: LLM_API_KEY is not configured. Cannot transcribe image."

    base64_image = base64.b64encode(image_bytes).decode("utf-8")
    system_prompt = (
        "You are ZLP ReleaseGuard, a helpful payment-focused QA engineer assistant at ZaloPay.\n"
        "Your task is to transcribe all text, code, release notes, git diffs, PRDs, or impact analysis details present in the provided image.\n"
        "Output ONLY the exact transcribed text and code. Do not add any greeting, explanation, conversational text, or markdown code block wraps."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Please transcribe the content of this image in detail."},
                {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{base64_image}"}},
            ],
        },
    ]
    # OCR/vision uses the LLM_MODEL_OCR role so a multimodal model can be configured
    # separately from the text-only chat/rewrite model.
    transcribed = llm_client.chat_completion(messages, role="ocr", temperature=0.1, timeout=60)
    if transcribed is None:
        return "Error transcribing image: the vision model is unavailable or returned no text."
    return clean_latex_symbols(transcribed)
