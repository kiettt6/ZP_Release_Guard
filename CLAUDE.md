# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .

# Run (dev — auto-reload, port 8000)
uvicorn zp_release_guard.api:app --reload --host 127.0.0.1 --port 8000

# Run (AgentBase-compatible, port 8080)
python main.py

# Tests
python -m pytest
python -m pytest tests/test_rca_risks.py   # single file
python -m pytest -k test_installment       # single test
```

Health and smoke:
```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/analyze-freeform \
  -H 'Content-Type: application/json' \
  -d '{"message":"Release Notes v2.8.1 cashback campaign for merchant QR payments.","project_hint":"zalopay"}'
```

## Architecture

The pipeline is fully deterministic — no LLM in the critical path. The optional `rewrite_report_with_llm` call in `report.py` is a cosmetic post-processor that rewrites the markdown; it is skipped entirely during pytest and when `LLM_API_KEY` is not set.

```
Input text (web chat / POST /analyze-freeform / POST /invocations)
  └─ analyzer.analyze_freeform()
       ├─ redaction.redact_secrets()         — strip bearer tokens, JWTs, API keys
       ├─ language.clean_latex_symbols()     — normalize LaTeX escapes to Unicode
       ├─ language.response_language_for()   — detect Vietnamese vs English
       ├─ parser.detect_input_types()        — classify: git_diff / impact_analysis_doc / prd_text / release_note / bugfix_summary / change_request_doc / merge_request_doc / rca_incident_doc / rollout_checklist
       ├─ domains.detect_domains()           — match ZaloPay domain signals (wallet_balance, refund, ledger, …)
       ├─ parser.collect_evidence()          — extract snippets for the report
       ├─ risks.detect_risks()              — run RISK_RULES keyword engine + domain baseline scoring
       ├─ risks.overall_risk()              — aggregate to CRITICAL / HIGH / MEDIUM / LOW
       ├─ report.recommendation_for()       — Go / Conditional Go / No-Go
       ├─ report.render_markdown_report()   — build full structured QA report
       └─ report.rewrite_report_with_llm()  — optional LLM rewrite (skipped in tests)
```

### Key module responsibilities

| Module | Responsibility |
|---|---|
| `models.py` | Pydantic schemas: `AnalyzeRequest/Response`, `Finding`, `ReleaseContext`, `RiskLevel`, `Recommendation` |
| `parser.py` | Regex-based input-type detection; evidence extraction |
| `domains.py` | Keyword → ZaloPay domain mapping (23 domains, incl. Tap2Pay/Visa, Installment/PayLater, Agreement Pay, Bank Connector/VietQR, User Management (UM) — sourced from Confluence space ZTM) |
| `risks.py` | `RISK_RULES` list (require_any / missing_all keyword rules); domain baseline scoring; `detect_risks()` |
| `report.py` | Report template with 11 sections; English/Vietnamese translation tables; LLM rewrite with validation guard |
| `knowledge.py` | Keyword-routed knowledge base (17 deep blocks từ Confluence ZTM + PD, gồm `bank_connector`: kiến trúc bc-api/receiver, catalog −9xxx/−5xxx, callback idempotency, deploy order shared-lib→receiver→api): `select_knowledge()` chấm điểm block theo keyword/mã lỗi trong câu hỏi, inject tối đa 3-4 block liên quan vào system prompt của chat engine và LLM rewrite. Blocks chứa bảng mã lỗi đầy đủ (transfer/topup −8xxx, agreement pay, eKYC DR/reason codes), MTI/Pismo, reconciliation matrix, UM flow state machines, NBA fact_ids |
| `language.py` | Vietnamese text detection; diacritic normalization; LaTeX symbol cleanup |
| `redaction.py` | Regex redaction of secrets before processing and in evidence snippets |
| `analyzer.py` | Thin orchestrator wiring all modules together |
| `api.py` | FastAPI app; `/health`, `/chat`, `/chat-upload`, `/analyze-freeform`, `/invocations` |
| `chat_engine.py` | Web chat engine; multi-turn context, `/sample` command, follow-up handling, OCR/PDF/DOCX extraction helpers |

### Risk rules (`risks.py`)

Each rule in `RISK_RULES` has:
- `requires_any` — Vietnamese-normalized keyword list that must match
- `missing_all` — mitigation keywords; if any present, rule is suppressed

Rules fire only when the mitigations are absent. The normalized text (diacritics stripped) is matched, so Vietnamese and transliterated Vietnamese both work.

The cross-check rule at the bottom of `detect_risks()` is a special case: it compares declared scope (`refund only`) against diff surface (`ledger/schema`) to catch underreported impact.

### Bilingual support

`language.response_language_for()` detects Vietnamese via diacritics or a VIETNAMESE_WORDS token-frequency threshold (≥3 hits). The report renderer branches on this to output translated section headers, bullets, and rationale from static translation dicts in `report.py`.

### Runtime modes

| Mode | Entry point | Port |
|---|---|---|
| production/local API | `main.py` → uvicorn | 8080 |
| dev reload | `uvicorn ... --reload` | 8000 |

## Environment variables

Copy `.env.example` to `.env`. Key variables:

| Variable | Purpose |
|---|---|
| `LLM_API_KEY` | Enables all LLM features; skipped if unset (graceful fallback) |
| `LLM_BASE_URL` | LLM endpoint (default: VNG MaaS) |
| `LLM_MODEL` | Default model for all roles |
| `LLM_ENABLE_REWRITE` | Enable the optional LLM report rewrite (default `false`) |
| `APP_API_KEY` | If set, the LLM-calling endpoints require header `X-API-Key` |
| `RATE_LIMIT_PER_MINUTE` | Per-IP cap on `/chat`, `/chat-upload`, `/analyze-freeform`, `/invocations` (default 120) |

All LLM calls go through `llm_client.chat_completion()` (centralized retry/backoff, per-role model selection, logging). Chat/upload inputs are redacted (`redact_secrets`) at the LLM boundary. `api.py` adds three middlewares: `enforce_request_size`, `enforce_access` (API key + rate limit), `add_security_headers` (incl. CSP).

## Adding new risk rules

Add entries to `RISK_RULES` in `risks.py`. Follow the pattern:
```python
{
    "title": "...",
    "severity": RiskLevel.CRITICAL,   # or HIGH / MEDIUM
    "category": "...",
    "requires_any": ["keyword1", "tu khoa tieng viet"],
    "missing_all": ["mitigation1", "bien phap giam thieu"],
    "rationale": "...",
}
```

Write a paired test in `tests/test_rca_risks.py` with a trigger case and a mitigated case (same pattern as existing tests).

The LLM system prompt in `report.rewrite_report_with_llm()` contains ZaloPay business context (partner names, DB tables, settlement cycles, known incident patterns). Update that section when onboarding new partners or after major production incidents.
