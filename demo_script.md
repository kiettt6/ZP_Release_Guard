# Demo Script

## 2-3 Minute Flow

1. Open with the release QA problem.
   Dev impact analysis often says the change is narrow, but payment releases can still affect idempotency, ledger consistency, reconciliation, token security, or old app behavior.

2. Start API locally.

```bash
uvicorn zp_release_guard.api:app --reload --host 127.0.0.1 --port 8000
```

3. Show the web chatbox sample command.

```text
/sample refund
```

Highlight:

- Risk is Critical.
- Recommendation is No-Go.
- Cross-check finding catches refund-only scope while diff includes ledger schema change.
- P0 smoke checklist calls out idempotency, debit-credit balance, rollback, audit, and partner-timeout refund scenarios.

4. Paste combined impact doc and diff into the web chatbox.

```text
/analyze Impact Analysis
Scope: refund only.
Change: retry refund when partner timeout happens.
diff --git a/db/migrations/202606_add_ledger_refund_idx.sql b/db/migrations/202606_add_ledger_refund_idx.sql
+ ALTER TABLE ledger_journal ADD COLUMN refund_retry_id varchar(64);
```

5. Close with Jira/PR comment.
   Show that the generated comment can be pasted into a PR or release Jira to request concrete P0 evidence before production.
