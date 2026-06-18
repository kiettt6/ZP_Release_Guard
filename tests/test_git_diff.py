from zp_release_guard.parser import (
    collect_evidence,
    detect_input_types,
    drop_removed_diff_lines,
    parse_git_diff,
)
from zp_release_guard.domains import detect_domains
from zp_release_guard.risks import detect_risks


SAMPLE_DIFF = """diff --git a/services/refund_worker.py b/services/refund_worker.py
index 1111111..2222222 100644
--- a/services/refund_worker.py
+++ b/services/refund_worker.py
@@ -10,6 +10,8 @@ def refund(order_id):
-    old_helper(order_id)
+    retry_refund(order_id, amount)
+    emit_partner_callback(order_id)
diff --git a/db/migrations/202606_add_ledger_refund_idx.sql b/db/migrations/202606_add_ledger_refund_idx.sql
+ ALTER TABLE ledger_journal ADD COLUMN refund_retry_id varchar(64);
"""


# --- parse_git_diff ---------------------------------------------------------

def test_parse_git_diff_extracts_files_and_lines() -> None:
    summary = parse_git_diff(SAMPLE_DIFF)
    assert summary.files == [
        "services/refund_worker.py",
        "db/migrations/202606_add_ledger_refund_idx.sql",
    ]
    assert "retry_refund(order_id, amount)" in summary.added_lines
    assert "ALTER TABLE ledger_journal ADD COLUMN refund_retry_id varchar(64);" in summary.added_lines
    assert "old_helper(order_id)" in summary.removed_lines
    # Metadata lines must not leak into code lines.
    assert all("index 1111111" not in line for line in summary.added_lines + summary.removed_lines)
    assert summary.hunk_headers and summary.hunk_headers[0].startswith("@@")


def test_parse_git_diff_empty_for_plain_text() -> None:
    assert parse_git_diff("Just a plain release note, no diff here.").is_empty


# --- drop_removed_diff_lines ------------------------------------------------

def test_drop_removed_diff_lines_keeps_added_drops_removed() -> None:
    cleaned = drop_removed_diff_lines(SAMPLE_DIFF)
    assert "old_helper(order_id)" not in cleaned
    assert "retry_refund(order_id, amount)" in cleaned


def test_drop_removed_diff_lines_preserves_markdown_bullets() -> None:
    text = "Scope:\n- refund only\n- no ledger change"
    # No diff region, so bullets must survive untouched.
    assert drop_removed_diff_lines(text) == text


# --- domain signals from file paths -----------------------------------------

def test_detect_domains_from_diff_file_paths() -> None:
    domains = detect_domains(SAMPLE_DIFF)
    # ledger_journal sits behind underscores in the path; flattening lets it match.
    assert "ledger_audit_log" in domains
    assert "refund" in domains


# --- diff-only risk rules ---------------------------------------------------

def test_money_critical_file_rule_triggers() -> None:
    findings = detect_risks(SAMPLE_DIFF, [], ["git_diff"])
    titles = [f.title for f in findings]
    assert "Git diff touches money-critical files without reconciliation or rollback coverage." in titles


def test_money_critical_file_rule_mitigated() -> None:
    mitigated = SAMPLE_DIFF + "\nReconciliation re-run and rollback (down migration) verified in staging.\n"
    findings = detect_risks(mitigated, [], ["git_diff"])
    titles = [f.title for f in findings]
    assert "Git diff touches money-critical files without reconciliation or rollback coverage." not in titles


def test_removed_guard_rule_triggers() -> None:
    diff = """diff --git a/auth/fundout.py b/auth/fundout.py
@@ -1,3 +1,2 @@
-    require_mfa(user)
+    proceed(user)
"""
    findings = detect_risks(diff, [], ["git_diff"])
    titles = [f.title for f in findings]
    assert "Git diff removes a protection (idempotency, auth, or risk gate) without a visible replacement." in titles


def test_removed_guard_rule_not_triggered_when_guard_retained() -> None:
    diff = """diff --git a/auth/fundout.py b/auth/fundout.py
@@ -1,3 +1,3 @@
-    require_mfa(user, legacy=True)
+    require_mfa(user)
"""
    findings = detect_risks(diff, [], ["git_diff"])
    titles = [f.title for f in findings]
    assert "Git diff removes a protection (idempotency, auth, or risk gate) without a visible replacement." not in titles


# --- diff-aware evidence ----------------------------------------------------

def test_collect_evidence_lists_changed_files() -> None:
    types = detect_input_types(SAMPLE_DIFF)
    evidence = collect_evidence(SAMPLE_DIFF, types)
    diff_snippets = [e.snippet for e in evidence if e.source == "git_diff"]
    assert any("services/refund_worker.py" in s for s in diff_snippets)
    assert any("db/migrations/202606_add_ledger_refund_idx.sql" in s for s in diff_snippets)
