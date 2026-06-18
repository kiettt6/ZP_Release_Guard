import re
from dataclasses import dataclass, field

from zp_release_guard.models import Evidence
from zp_release_guard.redaction import evidence_snippet


# --- Git diff parsing -------------------------------------------------------
# These power the diff-aware paths in domains.detect_domains and risks.detect_risks.
# A diff is structurally different from prose: changed file paths and added (+)
# vs removed (-) lines carry distinct meaning, so we extract them explicitly
# instead of treating the whole blob as flat text.
_DIFF_GIT_RE = re.compile(r"(?m)^diff --git a/(\S+) b/(\S+)")
_PLUS_FILE_RE = re.compile(r"(?m)^\+\+\+ b/(\S+)")
_DIFF_META_PREFIXES = (
    "index ", "new file", "deleted file", "rename ", "similarity ",
    "old mode", "new mode", "copy ", "dissimilarity ", "Binary files",
)


@dataclass
class GitDiffSummary:
    files: list[str] = field(default_factory=list)        # changed file paths (b/ side)
    added_lines: list[str] = field(default_factory=list)  # content of '+' lines (no leading +)
    removed_lines: list[str] = field(default_factory=list)  # content of '-' lines (no leading -)
    hunk_headers: list[str] = field(default_factory=list)  # '@@ ... @@' lines

    @property
    def is_empty(self) -> bool:
        return not (self.files or self.added_lines or self.removed_lines)


def parse_git_diff(message: str) -> GitDiffSummary:
    """Split a unified git diff into changed files and added/removed code lines.

    Tolerant of the abbreviated form used in samples (e.g. ``+ foo()`` with no
    hunk header). Diff metadata lines (index/mode/rename) and hunk headers are
    not treated as code.
    """
    summary = GitDiffSummary()
    in_diff = False
    for line in message.splitlines():
        if line.startswith("diff --git "):
            in_diff = True
            match = _DIFF_GIT_RE.match(line)
            if match:
                path = match.group(2)
                if path not in summary.files and path != "dev/null":
                    summary.files.append(path)
            continue
        if line.startswith("+++ ") or line.startswith("--- "):
            in_diff = True
            match = _PLUS_FILE_RE.match(line)
            if match and match.group(1) not in summary.files and match.group(1) != "dev/null":
                summary.files.append(match.group(1))
            continue
        if line.startswith("@@"):
            in_diff = True
            summary.hunk_headers.append(line.strip())
            continue
        if not in_diff:
            continue
        if any(line.startswith(prefix) for prefix in _DIFF_META_PREFIXES):
            continue
        if line.startswith("+"):
            content = line[1:].strip()
            if content:
                summary.added_lines.append(content)
        elif line.startswith("-"):
            content = line[1:].strip()
            if content:
                summary.removed_lines.append(content)
    return summary


def drop_removed_diff_lines(message: str) -> str:
    """Return *message* with removed (-) diff lines stripped, keeping prose intact.

    Risk keyword matching must not see deleted code: a guard keyword that exists
    only on a removed line would otherwise wrongly read as 'still present' and
    suppress a finding. Only lines inside a diff region are dropped, so markdown
    bullets ("- foo") outside a diff are preserved.
    """
    out: list[str] = []
    in_diff = False
    for line in message.splitlines():
        if line.startswith("diff --git "):
            in_diff = True
        elif line.startswith("@@"):
            in_diff = True
        if in_diff and line.startswith("-") and not line.startswith("--- "):
            continue
        out.append(line)
    return "\n".join(out)


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
        if input_type == "git_diff":
            # Diff-aware evidence: surface the changed file paths (a strong impact
            # signal) instead of a raw "+++ b/..." header line.
            summary = parse_git_diff(message)
            for path in summary.files[:5]:
                evidence.append(Evidence(source="git_diff", snippet=evidence_snippet(f"changed file: {path}")))
            if not summary.files and summary.hunk_headers:
                evidence.append(Evidence(source="git_diff", snippet=evidence_snippet(summary.hunk_headers[0])))
            continue
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
