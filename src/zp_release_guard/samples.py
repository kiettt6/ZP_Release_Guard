SAMPLES: dict[str, str] = {
    "refund": """Impact Analysis
Scope: refund only.
Change: retry refund when partner timeout happens.
Out of scope: wallet balance and settlement.

diff --git a/services/refund_worker.py b/services/refund_worker.py
+ retry_refund(order_id, amount)
+ emit_partner_callback(order_id)
diff --git a/db/migrations/202606_add_ledger_refund_idx.sql b/db/migrations/202606_add_ledger_refund_idx.sql
+ ALTER TABLE ledger_journal ADD COLUMN refund_retry_id varchar(64);
""",
    "promo": """Release Notes v2.8.1
New cashback campaign for merchant QR payments.
Users receive reward after successful payment.
Campaign supports voucher stacking and daily quota.
""",
    "banklink": """PRD: Bank linking refresh
Requirement: update linked bank token exchange and mobile app response.
Acceptance criteria: user can link, unlink, and relink bank account.
Risk: partner API timeout can happen during token exchange.
""",
}


def get_sample(name: str) -> str | None:
    return SAMPLES.get(name.lower().strip())
