import re

from zp_release_guard.models import Evidence
from zp_release_guard.redaction import evidence_snippet


INPUT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "git_diff": [
        re.compile(r"(?m)^diff --git "),
        re.compile(r"(?m)^\+\+\+ b/"),
        re.compile(r"(?m)^@@ .+ @@"),
    ],
    "impact_analysis_doc": [
        re.compile(r"(?i)\bimpact analysis\b"),
        re.compile(r"(?i)\bimpacted?\s+(module|service|flow|scope)s?\b"),
        re.compile(r"(?i)\bout of scope\b"),
        # Section headers từ template "Code Change Impact Analysis" (Confluence ZTM)
        re.compile(r"(?i)\bscope of change\b"),
        re.compile(r"(?i)t(á|a)c (đ|d)(ộ|o)ng k(ỹ|y) thu(ậ|a)t"),
        re.compile(r"(?i)(đ|d)(á|a)nh gi(á|a) r(ủ|u)i ro"),
        re.compile(r"(?i)thu h(ồ|o)i & gi(á|a)m s(á|a)t"),
        re.compile(r"(?i)ph(â|a)n lo(ạ|a)i thay (đ|d)(ổ|o)i"),
    ],
    "prd_text": [
        re.compile(r"(?i)\bprd\b"),
        re.compile(r"(?i)\bacceptance criteria\b"),
        re.compile(r"(?i)\bbusiness rule\b"),
        re.compile(r"(?i)\brequirement\b"),
    ],
    "release_note": [
        re.compile(r"(?i)\brelease notes?\b"),
        re.compile(r"(?i)\bversion\s+v?\d+(?:\.\d+)*\b"),
        re.compile(r"(?i)\bchangelog\b"),
    ],
    "bugfix_summary": [
        re.compile(r"(?i)\bbug\s*fix\b"),
        re.compile(r"(?i)\bhotfix\b"),
        re.compile(r"(?i)\bfixed\b"),
        re.compile(r"(?i)\broot cause\b"),
    ],
    # --- Các loại tài liệu theo template chuẩn trong Confluence space ZTM ---
    "change_request_doc": [
        re.compile(r"(?i)\bchange request\b"),
        re.compile(r"(?i)requirement \(choose 1 from 3\)"),
        re.compile(r"(?i)need to restart services\?"),
        re.compile(r"(?i)rollout plan, feature flag, migration, or backfill"),
    ],
    "merge_request_doc": [
        re.compile(r"(?i)\bmerge request\b"),
        re.compile(r"(?i)purpose & motivation \(why\)"),
        re.compile(r"(?i)key changes \(what\)"),
        re.compile(r"(?i)verification & testing \(how\)"),
        re.compile(r"(?i)\bproblem & solution\b"),
        re.compile(r"(?i)\bproof of execution\b"),
        re.compile(r"(?i)\bauthor checklist\b"),
    ],
    "rca_incident_doc": [
        re.compile(r"(?i)\brca\b"),
        re.compile(r"(?i)\bincident summary\b"),
        re.compile(r"(?i)\bevent timeline\b"),
        re.compile(r"(?i)\bincident responsibility\b"),
        re.compile(r"(?i)\bfollow up actions\b"),
    ],
    "rollout_checklist": [
        re.compile(r"(?i)\brollout checklist\b"),
        re.compile(r"(?i)\bdeployment steps\b"),
        re.compile(r"(?i)\bcicd ticket\b"),
        re.compile(r"(?i)\bservice dependenc(y|ies)\b"),
    ],
}


def detect_input_types(message: str) -> list[str]:
    detected = [name for name, patterns in INPUT_PATTERNS.items() if any(pattern.search(message) for pattern in patterns)]
    return detected or ["freeform_change_summary"]


def collect_evidence(message: str, detected_types: list[str]) -> list[Evidence]:
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    evidence: list[Evidence] = []

    for input_type in detected_types:
        patterns = INPUT_PATTERNS.get(input_type, [])
        for line in lines:
            if any(pattern.search(line) for pattern in patterns):
                evidence.append(Evidence(source=input_type, snippet=evidence_snippet(line)))
                break

    risk_terms = (
        "refund",
        "ledger",
        "balance",
        "idempot",
        "retry",
        "timeout",
        "callback",
        "token",
        "kyc",
        "settlement",
        "cashback",
        "voucher",
        "bank",
        "schema",
        "migration",
        "sftp",
        "payout",
        "replay",
        "backfill",
        "restore",
        "kafka",
        "dto",
        "mti",
        "doi soat",
    )
    for line in lines:
        lowered = line.lower()
        if any(term in lowered for term in risk_terms):
            snippet = evidence_snippet(line)
            if all(item.snippet != snippet for item in evidence):
                evidence.append(Evidence(source="risk_signal", snippet=snippet))
        if len(evidence) >= 10:
            break

    if not evidence:
        evidence.append(Evidence(source="freeform", snippet=evidence_snippet(message)))
    return evidence
