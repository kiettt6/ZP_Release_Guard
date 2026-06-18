import re

from zp_release_guard.language import normalize_vietnamese_text


DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "wallet_balance": ["wallet", "balance", "available balance", "hold balance", "so du", "vi"],
    "top_up": ["top up", "topup", "nap tien", "nap vi", "deposit"],
    "payment": ["payment", "pay", "checkout", "purchase", "order", "thanh toan", "don hang"],
    "refund": ["refund", "refunds", "reversal", "chargeback", "void", "hoan tien", "hoan tra"],
    "transfer": ["transfer", "p2p", "send money", "chuyen tien"],
    "cashback_reward": ["cashback", "reward", "loyalty", "coin", "hoan tien", "thuong"],
    "voucher_promotion": ["voucher", "promotion", "promo", "campaign", "coupon", "khuyen mai", "ma giam gia"],
    "merchant_payment": ["merchant", "qr", "pos", "mpos"],
    "bank_linking": ["bank link", "bank linking", "linked bank", "account binding", "lien ket ngan hang", "cashin", "cashout", "ibft"],
    "card_tokenization": ["card", "tokenization", "pan", "cvv", "card token", "the", "token the"],
    "kyc_account_status": ["kyc", "account status", "blocked account", "verified", "xac minh", "khoa tai khoan", "nfc", "ekyc", "e-kyc", "cccd", "can cuoc", "cmnd", "dinh danh", "vneid", "trueid", "bca", "ocr", "dr rule", "face authen", "liveness", "sinh trac hoc"],
    "risk_fraud": ["fraud", "risk", "abuse", "velocity", "rate limit"],
    "notification": ["notification", "push", "sms", "email", "webhook"],
    "settlement_reconciliation": ["settlement", "reconciliation", "recon", "clearing", "doi soat", "quyet toan", "settlement file", "sftp", "payout", "disbursement", "sao ke", "chi ho", "so phu"],
    "ledger_audit_log": ["ledger", "journal", "debit", "credit", "audit log", "double-entry", "so cai", "but toan", "hach toan"],
    "app_compatibility": ["old app", "backward", "compatibility", "ios", "android", "mobile app"],
    # --- Domains học từ Confluence space ZTM ---
    "tap2pay_card_processing": ["tap2pay", "tap to pay", "visa", "pismo", "mti", "processing code", "iso 8583", "pan token", "rrn", "stan", "chargeback", "authorization advice", "reversal advice", "the quoc te"],
    "installment_paylater": ["installment", "bnpl", "paylater", "pay later", "repayment", "ngan hang", "gach no", "tra no", "du no", "tra gop"],
    "agreement_autopay": ["agreement pay", "autopay", "auto-debit", "autodebit", "binding", "pay token", "paybytoken", "zptoken", "uy quyen thanh toan", "thoa thuan thanh toan", "lien ket vi"],
    "bank_connector": ["bc-api", "bc-bank-receiver", "bankqrreceiver", "bank connector", "bank callback", "bank statement", "vietqr", "upi", "virtual account", "bien dong so du", "cashin", "cashout", "ibft", "escrow account", "tai khoan dam bao", "returncodemapping", "bankfunction", "disbursement", "rba callback"],
    "bus_ticketing_travel": ["bus ticketing", "anvui", "futa", "vexere", "distribusion", "travel-booking", "seat map", "nha xe", "ve xe", "dat ve", "chuyen di"],
    "mobile_release_regression": ["final regression", "candidate branch", "candidate build", "release sign-off", "store review", "waiver list", "kiem thu hoi quy", "nhanh phat hanh"],
    "user_management": [
        "login", "logout", "session", "onboarding", "sim recycling", "welcome back",
        "pin", "change pin", "reset pin", "resetpinv2", "mktt", "mat khau thanh toan",
        "otp", "smart otp", "kba", "mfa", "authen challenge",
        "tlsd", "thanh ly so du", "liquidate balance",
        "lock account", "close account", "out-app ticket", "flow_token",
        "user-owner-framework", "user-pin-public", "user-otp", "user-vneid", "vneid-connector", "user-ekyc-nfc",
        "dang nhap", "dang ky", "doi mat khau", "quen mat khau", "dong tai khoan", "doi so dien thoai",
    ],
}


def detect_domains(message: str) -> list[str]:
    lowered = normalize_vietnamese_text(message.lower())
    # Diff file paths carry strong domain signals (e.g. db/migrations/..._ledger_...sql)
    # but their / _ . - separators block \bword\b matching. Flatten path segments
    # into space-separated tokens so keywords like "ledger"/"refund" match.
    path_tokens = " ".join(
        re.sub(r"[\\/_.\-]", " ", match.group(1))
        for match in re.finditer(r"(?m)^diff --git a/\S+ b/(\S+)", message)
    )
    if path_tokens:
        lowered = lowered + "\n" + normalize_vietnamese_text(path_tokens.lower())
    domains: list[str] = []
    for domain, keywords in DOMAIN_KEYWORDS.items():
        if any(re.search(rf"\b{re.escape(keyword)}\b", lowered) for keyword in keywords):
            domains.append(domain)
    return domains or ["general_release_change"]
