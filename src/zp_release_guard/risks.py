import re

from zp_release_guard.language import normalize_vietnamese_text
from zp_release_guard.models import Finding, RiskLevel


CRITICAL_DOMAINS = {
    "wallet_balance",
    "payment",
    "refund",
    "settlement_reconciliation",
    "ledger_audit_log",
    "tap2pay_card_processing",
    "installment_paylater",
}
HIGH_DOMAINS = {
    "bank_linking",
    "card_tokenization",
    "kyc_account_status",
    "risk_fraud",
    "merchant_payment",
    "agreement_autopay",
    "bank_connector",
    "user_management",
}


RISK_RULES = [
    # =========================================================================
    # CRITICAL — có thể ảnh hưởng trực tiếp đến tiền của khách hàng
    # =========================================================================
    {
        "title": "Missing idempotency coverage for retryable money movement.",
        "severity": RiskLevel.CRITICAL,
        "category": "Idempotency",
        # BẮT KHI: text đề cập retry / timeout / callback / duplicate trong luồng tiền.
        # Không bắt chỉ vì có chữ refund/payment; nếu không, các đổi rule amount đơn giản
        # sẽ bị nâng sai lên Critical idempotency.
        "requires_any": ["retry", "timeout", "callback", "duplicate", "replay", "repush", "backfill", "thu lai", "qua han", "trung"],
        "requires_any_context": ["refund", "refunds", "payment", "hoan tien", "thanh toan"],
        # KHÔNG BẮT NẾU: đã đề cập cách chống duplicate
        "missing_all": ["idempotency", "idempotent", "dedupe", "request id", "unique key", "chong trung", "ma duy nhat"],
        "rationale": "Retryable payment/refund paths can double debit, double refund, or emit duplicate callbacks without a stable idempotency contract.",
    },
    {
        "title": "Ledger and reconciliation impact is not explicitly covered.",
        "severity": RiskLevel.CRITICAL,
        "category": "Ledger",
        "requires_any": ["ledger", "journal", "schema", "migration", "debit", "credit", "balance", "so cai", "but toan", "hach toan", "so du"],
        "missing_all": ["reconciliation", "recon", "double-entry", "settlement", "audit", "doi soat", "quyet toan", "kiem toan"],
        "rationale": "Ledger or balance changes need debit-credit consistency, settlement matching, and auditable rollback validation.",
    },
    {
        # ← TEMPLATE: thêm rule từ incident thực tế của team
        # Ví dụ: "lần trước migration không có rollback, production sập 2h"
        "title": "DB migration thiếu rollback script hoặc down migration.",
        "severity": RiskLevel.CRITICAL,
        "category": "Migration",
        # BẮT KHI: có thay đổi schema DB
        # ← điền thêm keyword thực tế: tên tool migration (liquibase, flyway...), tên bảng quan trọng
        "requires_any": [
            "migration", "alter table", "drop column", "add column", "drop table",
            "create index", "schema change", "db change", "liquibase", "flyway",
            "thay doi bang", "them cot", "xoa cot",
        ],
        # KHÔNG BẮT NẾU: đã có plan rollback
        # ← điền thêm keyword team bạn dùng khi viết rollback plan
        "missing_all": [
            "rollback", "revert", "down.sql", "down migration", "undo",
            "backup", "hoan tac", "khoi phuc",
        ],
        "rationale": "Schema migration không có rollback script có thể gây mất dữ liệu hoặc downtime kéo dài nếu deploy fail.",
    },

    # =========================================================================
    # HIGH — rủi ro nghiêm trọng, cần QA sign-off trước khi release
    # =========================================================================
    {
        "title": "Refund state transition and compensation rules need QA sign-off.",
        "severity": RiskLevel.HIGH,
        "category": "Refund",
        "requires_any": ["refund", "refunds", "reversal", "void", "hoan tien", "hoan tra"],
        "missing_all": ["state", "transition", "partial", "compensation", "rollback", "trang thai", "mot phan", "boi hoan"],
        "rationale": "Refund flows often fail in partial success and partner-timeout states unless state transitions and compensation paths are tested.",
    },
    {
        "title": "Financial amount precision and rounding rules are not stated.",
        "severity": RiskLevel.HIGH,
        "category": "Financial math",
        "requires_any": ["amount", "fee", "cashback", "voucher", "discount", "currency", "balance", "so tien", "phi", "giam gia", "tien te", "so du"],
        "missing_all": ["decimal", "rounding", "precision", "scale", "minor unit", "lam tron", "do chinh xac"],
        "rationale": "Payment math needs deterministic decimal handling across fees, discounts, cashback, and displayed versus ledger amounts.",
    },
    {
        "title": "Refund minimum-amount threshold change needs boundary and reconciliation coverage.",
        "severity": RiskLevel.HIGH,
        "category": "Refund",
        "requires_any": ["refund", "refunds", "hoan tien"],
        "requires_all": ["vnd"],
        "missing_all": ["boundary test", "min amount", "minimum amount", "decimal", "rounding", "reconciliation", "doi soat", "ledger"],
        "rationale": "Allowing refunds below a previous money threshold can bypass amount validation, fee/reversal rules, partner settlement assumptions, or ledger reconciliation if boundary cases are not tested.",
    },
    {
        "title": "Token/session security controls are not visible.",
        "severity": RiskLevel.HIGH,
        "category": "Security",
        "requires_any": ["token", "session", "bank link", "card", "authorization", "oauth", "credential", "lien ket ngan hang", "the", "uy quyen"],
        "missing_all": ["expiry", "rotate", "encrypt", "tokenization", "owasp", "mask", "het han", "ma hoa", "che"],
        "rationale": "Bank/card/token changes must validate storage, masking, expiry, rotation, replay prevention, and OWASP API controls.",
    },
    {
        "title": "Promotion abuse and duplicate claim controls are missing.",
        "severity": RiskLevel.HIGH,
        "category": "Fraud",
        "requires_any": ["cashback", "voucher", "promotion", "campaign", "reward", "khuyen mai", "ma giam gia", "thuong"],
        "missing_all": ["abuse", "fraud", "rate limit", "velocity", "duplicate", "gian lan", "han muc", "trung"],
        "rationale": "Campaign changes need duplicate claim, quota, velocity, and refund-after-reward abuse coverage.",
    },
    {
        # ← TEMPLATE: batch job / scheduler hay gây incident vì re-run không idempotent
        "title": "Batch job hoặc scheduler thay đổi thiếu mô tả re-run safety.",
        "severity": RiskLevel.HIGH,
        "category": "Batch",
        # ← điền tên batch job / scheduler thực tế của team (settlement_job, recon_worker...)
        "requires_any": [
            "batch", "scheduler", "cron", "cronjob", "job", "worker",
            "settlement job", "recon job", "nightly job", "daily job",
            "xu ly hang loat", "chay lai",
        ],
        # KHÔNG BẮT NẾU: đã đề cập idempotency hoặc skip-if-done
        "missing_all": [
            "idempotent", "idempotency", "re-run", "rerun", "skip if",
            "already processed", "duplicate check", "da xu ly",
        ],
        "rationale": "Batch job chạy lại (retry hoặc rerun thủ công) có thể double-process transaction nếu không có idempotency guard.",
    },

    # =========================================================================
    # MEDIUM — cần chú ý, không block release nhưng phải document
    # =========================================================================
    {
        "title": "Old app compatibility and rollback behavior are unclear.",
        "severity": RiskLevel.MEDIUM,
        "category": "Compatibility",
        "requires_any": ["mobile", "android", "ios", "app", "api", "response", "contract"],
        "missing_all": ["old app", "backward", "compatibility", "rollback", "feature flag", "app cu", "tuong thich"],
        "rationale": "Mobile releases may remain mixed-version for weeks, so API response and feature flag fallback need explicit validation.",
    },
    {
        "title": "Monitoring and audit evidence are not described.",
        "severity": RiskLevel.MEDIUM,
        "category": "Observability",
        "requires_any": ["release", "change", "deploy", "payment", "refund", "bank", "cashback", "ledger", "phat hanh", "trien khai", "thanh toan", "hoan tien"],
        "missing_all": ["monitor", "alert", "dashboard", "audit", "log", "trace", "canh bao", "giam sat", "kiem toan"],
        "rationale": "Production payment releases need audit logs, traceability, and alert thresholds for early rollback decisions.",
    },
    {
        # ← TEMPLATE: thay đổi config / feature flag không có cách disable nhanh
        "title": "Thay đổi config hoặc feature flag thiếu disable/rollback plan.",
        "severity": RiskLevel.MEDIUM,
        "category": "Config",
        # ← điền tên config system của team (consul, configmap, remote config...)
        "requires_any": [
            "config", "feature flag", "toggle", "env", "environment variable",
            "remote config", "consul", "configmap", "property", "setting",
            "cau hinh", "bat tat",
        ],
        # KHÔNG BẮT NẾU: đã có plan tắt hoặc rollback config
        "missing_all": [
            "rollback", "revert", "disable", "turn off", "fallback",
            "kill switch", "tat tinh nang",
        ],
        "rationale": "Config thay đổi không có cách disable nhanh sẽ không kịp rollback nếu có incident trên production.",
    },
    {
        "title": "Installment repayment and partner debt settlement status mismatch.",
        "severity": RiskLevel.CRITICAL,
        "category": "Repayment",
        "requires_any": ["installment", "repayment", "bnpl", "paylater", "tra no", "gach no", "du no"],
        "missing_all": ["status verify", "verify payment status", "cross check status", "check status", "doi chieu trang thai", "kiem tra trang thai", "so sanh trang thai"],
        "rationale": "Installment/repayment flows must verify that the corresponding payment is successful before triggering debt settlement/repayment calls to the partner, to prevent un-debited fund loss or incorrect billing status.",
    },
    {
        "title": "Stale replica or sequence count causing duplicate transaction IDs (TransID).",
        "severity": RiskLevel.CRITICAL,
        "category": "ID Generation",
        "requires_any": ["transid", "genid", "id generator", "sequence generator", "sequence exhausted", "stale replica", "trung transid", "sinh ma"],
        "missing_all": ["validate transaction info", "amount match", "check user id", "validate query status", "doi chieu so tien", "trung khop uid"],
        "rationale": "Duplicate TransID errors in sequence generators (often caused by replica desynchronization) can map new transactions to old successful ones, leading to false success responses and order delivery without actual payments.",
    },
    {
        "title": "Merging Refund and Cancel logic leading to full refund on partial requests.",
        "severity": RiskLevel.HIGH,
        "category": "Refund",
        "requires_any": ["partial refund", "refund amount", "refund logic", "cancel and refund", "gop code refund", "hoan tien mot phan", "huy va hoan"],
        "missing_all": ["partial test", "amount check", "balance check", "verify refund amount", "kiem tra so tien", "test hoan mot phan"],
        "rationale": "Refactoring or optimization of refund/cancel handlers can lead to using original transaction amounts instead of requested partial refund amounts, causing direct fund loss.",
    },
    {
        "title": "Refactoring shared event parser or DTO without validation of automated/scheduled pipelines.",
        "severity": RiskLevel.HIGH,
        "category": "Event Parsing",
        "requires_any": ["event parser", "dto refactor", "payload change", "event processing", "auto query", "bill-event", "chuyen doi dto", "cau truc event", "job tu dong"],
        "missing_all": ["regression", "payload verification", "automated pipeline", "auto pipeline", "scheduled job test", "regression ca hai", "da xu ly"],
        "rationale": "Automated pipelines (e.g. daily query job) often consume different event payloads or DTO fields than manual user-triggered flows. Refactoring shared parsers without validating both flows can lead to silent data processing failures.",
    },
    {
        "title": "JSON configuration key case-sensitivity mismatch in rollout settings.",
        "severity": RiskLevel.HIGH,
        "category": "Config",
        "requires_any": ["rollout percent", "config serialization", "json property", "camelcase", "snake_case", "mismatch case", "viet hoa chu thuong", "sai ky tu config"],
        "missing_all": ["schema validation", "deserialization test", "validate json keys", "parse test", "kiem tra schema", "validate truong config"],
        "rationale": "Mismatches in field casing (e.g. rollOutPercent vs rolloutPercent) between JSON config payloads and Java/Go config classes can cause silent failures where rollout rules or limits are not applied.",
    },
    {
        "title": "Mobile app uses-feature or permission changes restricting device compatibility.",
        "severity": RiskLevel.HIGH,
        "category": "Compatibility",
        "requires_any": ["uses-feature", "uses-permission", "android permission", "nfc feature", "app requirement", "yeu cau phan cung", "quyen ung dung", "cai dat nfc"],
        "missing_all": ["compatibility check", "negative hardware test", "device compatibility verification", "kiem tra tuong thich", "test thiet bi khong ho tro"],
        "rationale": "Adding application permissions or hardware requirements (like NFC) can make the app incompatible with older or low-end devices, preventing users from installing or updating.",
    },
    {
        "title": "Stale parameters persistence in micro-app container due to state reuse.",
        "severity": RiskLevel.HIGH,
        "category": "Client State",
        "requires_any": ["micro-app", "microapp", "onresume", "on-resume", "state reuse", "stale parameters", "ios reload", "trang thai cu", "chuyen man hinh"],
        "missing_all": ["clear state", "onresume handler", "reset parameters", "updateurlneeded", "xoa cache trang thai", "reset tham so"],
        "rationale": "Reusing webview instances or micro-app containers without resetting URL parameters or state in the native onResume lifecycle can cause stale parameters (like old transaction info or QR codes) to persist, leading to incorrect actions (like transferring money to the previous recipient).",
    },
    {
        "title": "Third-party bank connector spec changes or missed error code mapping.",
        "severity": RiskLevel.MEDIUM,
        "category": "Partner Integration",
        "requires_any": ["techspec", "spec change", "error mapping", "partner error", "partner spec", "partner bank", "ma loi", "doi tac thay doi", "dac ta ky thuat"],
        "missing_all": ["spec alignment", "error code test", "verify error response", "reconciliation mapping", "chuan hoa ma loi", "doi chieu spec"],
        "rationale": "Changes in partner specs or missed error mapping (like ignoring error status 35) can cause failed third-party transactions to be falsely treated as successful, creating silent balance discrepancies.",
    },

    # =========================================================================
    # Rules học từ RCA/incident thực tế trong Confluence space ZTM
    # =========================================================================
    {
        "title": "Settlement file or delivery config change lacks maker-checker and merchant verification.",
        "severity": RiskLevel.HIGH,
        "category": "Settlement Ops",
        "requires_any": [
            "settlement file", "file doi soat", "delivery config", "settlement report",
            "repush file", "sftp folder", "sftp path", "file format", "merchant report",
            "thu muc sftp", "sao ke doi tac",
        ],
        "missing_all": [
            "maker checker", "maker-checker", "maker/checker", "four eyes", "4-eyes",
            "approval", "phe duyet", "cross-check", "kiem tra cheo",
            "merchant confirmation", "xac nhan merchant", "file delivery monitoring",
        ],
        "rationale": "Settlement file format, schedule, or delivery-config changes have repeatedly broken partner reconciliation (e.g. files delivered to a test folder for days). They need maker-checker approval, merchant-side confirmation, and delivery monitoring.",
    },
    {
        "title": "Callback/DTO field change lacks backward compatibility and contract test coverage.",
        "severity": RiskLevel.HIGH,
        "category": "Partner Contract",
        "requires_any": [
            "callback payload", "bank callback", "callback schema", "webhook payload",
            "dto", "field mapping", "rename field", "new field", "payload change",
            "api version", "them field", "truong moi", "doi ten field", "phien ban api",
        ],
        "missing_all": [
            "backward compatible", "backward compatibility", "contract test",
            "schema validation", "support both", "dual version",
            "tuong thich nguoc", "ho tro ca hai",
        ],
        "rationale": "Partner callback fields have been silently dropped or renamed across DTO chains (shared-lib, receiver, API), breaking old integrations or losing data with no alert. Field changes need contract tests and explicit backward compatibility.",
    },
    {
        "title": "Refactored or long-lived code may ride along on this release without scope review.",
        "severity": RiskLevel.HIGH,
        "category": "Release Scope",
        "requires_any": [
            "refactor", "merge main", "merge to main", "long-lived branch",
            "ride along", "tai cau truc", "gop nhanh", "code cu tren main",
        ],
        "missing_all": [
            "diff review", "git diff review", "release scope", "scope review",
            "qa sign-off", "qa signoff", "regression test", "changelog review",
            "xac nhan scope", "kiem thu hoi quy",
        ],
        "rationale": "Untested refactors merged to main months earlier have shipped accidentally alongside unrelated deploys and caused fund loss. Release notes must confirm a git-diff review between the production version and the deploy candidate.",
    },
    {
        "title": "Replay/repush/backfill operation lacks an idempotency or double-payout guard.",
        "severity": RiskLevel.HIGH,
        "category": "Recovery Ops",
        "requires_any": [
            "replay", "repush", "backfill", "re-run job", "rerun job",
            "chay lai job", "day lai message", "khoi phuc giao dich",
        ],
        "missing_all": [
            "idempotent", "idempotency", "duplicate check", "double payout guard",
            "skip if processed", "must update flag", "verify payout",
            "chong trung", "da xu ly",
        ],
        "rationale": "Recovery via Kafka replay, file repush, or data backfill risks double-processing and double payout unless every replayed item is idempotent and verified against already-settled records.",
    },
    {
        "title": "External dependency added or changed without failover or circuit breaker.",
        "severity": RiskLevel.MEDIUM,
        "category": "Resilience",
        "requires_any": [
            "napas", "vietqr", "third-party", "3rd party", "external sdk", "cdn",
            "external dependency", "external script", "ben thu ba", "doi tac ngoai",
        ],
        "missing_all": [
            "failover", "fallback", "circuit breaker", "switch bank", "multi-bank",
            "self-host", "du phong", "chuyen luong",
        ],
        "rationale": "Bank/Napas outages and third-party CDN failures are survivable only with multi-bank routing, fallback, or self-hosted assets. Single external dependencies without failover degrade payment availability.",
    },
    {
        "title": "Multi-service or shared-library release lacks an explicit deployment order.",
        "severity": RiskLevel.MEDIUM,
        "category": "Deployment",
        "requires_any": [
            "shared lib", "shared-lib", "common library", "bump version",
            "multiple services", "multi-service", "nhieu service", "lib chung",
        ],
        "missing_all": [
            "deploy order", "deployment order", "staged rollout", "rollout checklist",
            "verify in staging", "thu tu deploy", "deploy theo thu tu", "build theo thu tu",
        ],
        "rationale": "Releases spanning shared libraries and multiple dependent services break when components ship out of order. The rollout checklist must state the exact deployment sequence and a staging verification step.",
    },
    {
        "title": "Message consumer or merchant notification change lacks negative-path test and DLQ handling.",
        "severity": RiskLevel.HIGH,
        "category": "Messaging",
        "requires_any": [
            "kafka", "consumer", "message queue", "notify merchant",
            "notification flow", "thong bao giao dich",
        ],
        "missing_all": [
            "dead letter", "dlq", "retry", "replay", "negative test",
            "test pending", "error case test", "alert missing",
            "kiem thu truong hop loi",
        ],
        "rationale": "An early return on the pending/error branch of a consumer dropped merchant payment notifications right after release. Consumer changes need pending/failed-path tests, retry or DLQ handling, and a missing-message alert.",
    },
    {
        "title": "Data restore from backup lacks post-restore validation.",
        "severity": RiskLevel.HIGH,
        "category": "Data Recovery",
        "requires_any": [
            "restore backup", "restore from backup", "data restore", "etcd restore",
            "khoi phuc backup", "khoi phuc du lieu",
        ],
        "missing_all": [
            "data validation", "checksum", "verify after restore", "validate restored",
            "verify random sample", "kiem tra sau khoi phuc",
        ],
        "rationale": "A backup restore has silently truncated stored values and broken lookups (AppNotFound). Every restore needs post-restore validation: checksums, sample verification, and cross-system comparison.",
    },
    {
        # [EA][2025] Idempotency & Duplication: MTI 0x00 phải exactly-once,
        # advice 0x20 retry trên cùng bcTransID, mỗi payment tối đa 1 advice.
        "title": "Visa/Tap2Pay MTI processing change lacks exactly-once and advice-dedup guarantees.",
        "severity": RiskLevel.CRITICAL,
        "category": "Card Processing",
        "requires_any": [
            "mti", "0100", "0200", "0220", "0120", "0400", "0420",
            "advice message", "tap2pay", "pismo", "clearing",
        ],
        "missing_all": [
            "idempotency", "idempotent", "exactly once", "at most one advice",
            "lookback", "chi thuc hien 1 lan", "tra trang thai truoc do",
        ],
        "rationale": "Visa requires exactly-once processing per MTI 0x00 request and at most one advice (0x20) adjustment per payment, with retries on the same bcTransID. Changes here without these guarantees cause double debit or unmatched clearing.",
    },
    {
        "title": "Unbounded resource creation (dynamic topics, goroutines, connections) lacks load testing and limits.",
        "severity": RiskLevel.MEDIUM,
        "category": "Capacity",
        "requires_any": [
            "dynamic topic", "create topic", "per-request", "goroutine",
            "websocket", "tao topic", "spawn thread",
        ],
        "missing_all": [
            "load test", "resource limit", "connection pool", "rate limit",
            "bounded", "kiem thu tai", "gioi han tai nguyen",
        ],
        "rationale": "Dynamically created Kafka topics once took the shared cluster down, and a goroutine leak exhausted RAM/CPU into restart loops. New per-request resource creation needs hard limits and a load test.",
    },

    # =========================================================================
    # Rules cho domain UM (User Management) — học từ Confluence space ZTM
    # =========================================================================
    {
        "title": "Reset PIN / balance liquidation flow change lacks risk, MFA, or KBA gating.",
        "severity": RiskLevel.CRITICAL,
        "category": "Account Security",
        "requires_any": [
            "reset pin", "resetpinv2", "tlsd", "thanh ly so du", "liquidate balance",
            "unlink bank", "update pin", "doi mat khau thanh toan",
        ],
        "missing_all": [
            "risk check", "mfa", "rba", "kba", "otp verify", "face authen",
            "pending request check", "retry limit", "owner flow",
        ],
        "rationale": "Reset-PIN and balance-liquidation flows are gated by risk level (auto / RBA-MFA / manual owner flow), KBA blocking after failed attempts, and face authentication on untrusted devices. Removing or weakening any gate opens account takeover and fund-out risk.",
    },
    {
        "title": "OTP send endpoint change lacks anti-spam and abuse controls.",
        "severity": RiskLevel.HIGH,
        "category": "Account Security",
        "requires_any": [
            "send otp", "otp api", "otp endpoint", "send_otp_token",
            "phone status", "login by phone", "gui otp", "ma otp",
        ],
        "missing_all": [
            "rate limit", "risk engine", "risk checkpoint", "captcha",
            "blacklist", "chan spam", "anti-spam",
        ],
        "rationale": "OTP send endpoints have been abused in production for phone enumeration and SMS-OTP spam (replayed send_otp_token). Changes need per-phone/IP rate limits, a risk-engine checkpoint before sending, and captcha when spam is suspected.",
    },
    {
        "title": "Strict parsing of upstream profile/vendor response without lenient fallback.",
        "severity": RiskLevel.HIGH,
        "category": "Upstream Contract",
        "requires_any": [
            "zalo api", "social api", "get profile", "profile field", "birthday field",
            "vendor response", "trueid", "jth", "bca", "parse response",
        ],
        "missing_all": [
            "lenient parsing", "optional field", "default value", "fallback vendor",
            "graceful degradation", "tolerant parser", "bo qua field thieu",
        ],
        "rationale": "An upstream provider silently removing a profile field once broke login for ~52k requests/hour because parsing was strict. Upstream and eKYC vendor responses (TrueID, JTH, BCA) need lenient parsing, optional fields, and vendor fallback chains.",
    },
    {
        "title": "eKYC OCR/DR-rule blocking change lacks bypass, kill switch, or unknown-code fallback.",
        "severity": RiskLevel.HIGH,
        "category": "eKYC",
        "requires_any": [
            "dr-031", "dr-049", "dr rule", "ocr submit", "block submit",
            "mismatch_reasons", "chan submit", "ekyc decision",
        ],
        "missing_all": [
            "three-strike", "bypass", "kill switch", "a/b flag", "rollback",
            "unknown reason code", "fallback",
        ],
        "rationale": "Blocking eKYC OCR submission on DR rules is only safe with a three-strike backend bypass, an A/B kill switch, and unknown-reason-code no-op fallback for old apps. The OCR submit flow has no unit-test coverage, so manual validation is mandatory.",
    },
    {
        "title": "Backend decision-flow enum change without client mapping test and default case.",
        "severity": RiskLevel.MEDIUM,
        "category": "Client Contract",
        "requires_any": [
            "uidecisionflow", "decision flow", "df_type", "df_reason",
            "nfc verification flow", "enum mapping", "dieu huong ui",
        ],
        "missing_all": [
            "enum mapping test", "default case", "client fallback",
            "unknown enum", "backward compatible",
        ],
        "rationale": "Backend decision-flow enums (e.g. DF_TYPE_NFC_VERIFICATION with reasons NFC_PROCESSING/NEW_USER/FUND_OUT_LIMIT/BLACKLIST) drive client UI routing at fund-out time. New or renumbered values without a client default case misroute users.",
    },
    {
        "title": "CE/out-app ticket creation change lacks pending-ticket duplicate check.",
        "severity": RiskLevel.MEDIUM,
        "category": "Support Ops",
        "requires_any": [
            "ce ticket", "out-app ticket", "outapp ticket", "searchticket",
            "createticket", "gui yeu cau ho tro",
        ],
        "missing_all": [
            "check pending", "pending ticket check", "request_type filter",
            "status filter", "duplicate ticket",
        ],
        "rationale": "The app previously created duplicate CE support tickets because it never pre-checked pending tickets. Ticket-creation flows must search by the same request_type and pending-group statuses before creating a new one.",
    },
    {
        # Trường hợp đặc biệt: text nói rõ việc GỠ BỎ một gate xác thực
        # ("bỏ bước KBA", "skip risk check"...). Rule gate ở trên sẽ bị suppress
        # vì keyword mitigation xuất hiện, nên cần rule bắt cụm phủ định trực tiếp.
        "title": "An authentication or risk gate is being removed or weakened.",
        "severity": RiskLevel.CRITICAL,
        "category": "Account Security",
        "requires_any": [
            "bo buoc kba", "bo kba", "remove kba", "skip kba",
            "bo buoc otp", "remove otp step", "skip otp",
            "disable mfa", "bo mfa", "remove mfa",
            "skip risk check", "bo risk check", "remove risk check",
            "disable face authen", "bo face authen", "remove face authen",
            "giam friction", "reduce friction", "bypass authentication",
        ],
        "missing_all": [
            "security review", "risk approval", "compensating control",
            "da review security", "phe duyet risk", "duoc security approve",
        ],
        "rationale": "The release explicitly removes or weakens an authentication/risk gate (KBA, OTP, MFA, face authen, risk check) in a flow that protects account access or fund-out. This requires an explicit security review and a documented compensating control.",
    },

    # =========================================================================
    # Rules cho Bank Connector (BC)
    # =========================================================================
    {
        # -5000 BANK_ZION_ESCROW_ACCOUNT_BALANCE_EXCEEDED / -5800 LOCKED:
        # escrow/tài khoản đảm bảo hết số dư hoặc bị khóa làm FAIL mọi giao dịch
        # qua connector đó; -5000 là alert High-Critical ở ngưỡng 1 txn / 5m.
        "title": "Bank Connector escrow/guarantee account balance is not monitored.",
        "severity": RiskLevel.CRITICAL,
        "category": "Bank Connector",
        "requires_any": [
            "escrow account", "guarantee account", "tai khoan dam bao",
            "tai khoan bao dam thanh toan", "escrow balance", "wallet escrow",
            "disbursement", "ibft", "zion escrow", "-5000", "-5800",
        ],
        "missing_all": [
            "balance monitor", "ng-uong so du", "nguong so du", "balance alert",
            "escrow balance query", "alert threshold", "top-up escrow", "theo doi so du",
        ],
        "rationale": "If the ZaloPay escrow/guarantee account that funds a connector runs low or is locked (-5000/-5800), every transaction through that connector fails. The release must keep a balance monitor and an alert threshold (the -5000 alert fires at just 1 txn / 5m).",
    },
    {
        # Bank trả mã lỗi mới chưa được map trong returnCodeMapping (bcadm) →
        # convertResponse rơi vào default -5002/-9003, gây sai trạng thái giao dịch.
        "title": "Bank return-code mapping is not updated for new or changed bank codes.",
        "severity": RiskLevel.HIGH,
        "category": "Bank Connector",
        "requires_any": [
            "return code mapping", "returncodemapping", "convertresponse",
            "map bank code", "ma loi bank", "new error code", "ma loi moi",
            "bank response code", "error code mapping", "connector converter",
        ],
        "missing_all": [
            "mapping table updated", "mapping updated", "bcadm", "default code",
            "fallback code", "cap nhat mapping", "doi chieu mapping", "verify mapping",
        ],
        "rationale": "An unmapped bank return code falls through to a default (-5002/-9003) and mislabels the transaction status (e.g. a real failure shown as pending). The return-code mapping table must be updated and verified whenever a bank adds or changes codes.",
    },
    {
        # New bank / connector thiếu config bankFunction / BankInfo / BankConfig
        # → -8129 CHECK_BANK_CONFIG_NOTEXIST, -9207, -5027 SELECTOR_NOT_FOUND.
        "title": "New bank/connector config (bankFunction, BankInfo, BankConfig) may be missing.",
        "severity": RiskLevel.HIGH,
        "category": "Bank Connector",
        "requires_any": [
            "bankfunction", "bank function", "bankinfo", "bankconfig",
            "new bank", "ngan hang moi", "connector moi", "new connector",
            "tich hop ngan hang", "-8129", "bin management", "issuer code",
        ],
        "missing_all": [
            "config added", "da config", "cstool", "cmdb", "cdn tool",
            "reload config", "cache reload", "config verified", "kiem tra config",
        ],
        "rationale": "Integrating a new bank requires bankFunction codes (301/302/104/105/501/502/601/602) on the CDN tool plus BankInfo + BankConfig for withdraw; missing config yields -8129 CHECK_BANK_CONFIG_NOTEXIST or selector-not-found. Confirm the config is added and reloaded in every environment.",
    },
    {
        # Callback ngân hàng (IPN/RBA/QR push) bị xử lý trùng → fund loss.
        # Dedup qua bankIdempotencyLog/bcIdempotencyLog; mã -3020/-3021/-3024/-5043/-5057.
        "title": "Inbound bank callback handling lacks idempotency/dedup.",
        "severity": RiskLevel.CRITICAL,
        "category": "Bank Connector",
        "requires_any": [
            "bank callback", "ipn callback", "rba callback", "qr push", "inbound callback",
            "bankqrreceiver", "bc-bank-receiver", "bankidempotencylog", "callback handler",
            "bank initiated", "webhook ngan hang",
        ],
        "missing_all": [
            "idempotency", "idempotent", "dedup", "duplicate check", "trace no",
            "bcidempotencylog", "chong trung", "unique transid", "-3020", "-3024",
        ],
        "rationale": "Bank-initiated callbacks (IPN, RBA, QR push) can be delivered more than once; without an idempotency/dedup check (bankIdempotencyLog / dedup codes -3020/-3021/-3024/-5043) the same inbound event is processed twice, causing double credit or fund loss.",
    },
    {
        # Luồng sync (proxy hop) làm bank chậm chặn queue chung → -9205, lan sang
        # bank khỏe; async V3.1 + per-bank rate limit + 'transaction expired' isolate.
        "title": "Synchronous bank-call path can stall the shared queue (no slow-bank isolation).",
        "severity": RiskLevel.MEDIUM,
        "category": "Bank Connector",
        "requires_any": [
            "sync flow", "synchronous", "proxy hop", "connector call", "bank call",
            "-9205", "internal bc time out", "pending queue", "rabbitmq", "luong dong bo",
        ],
        "missing_all": [
            "async", "bat dong bo", "rate limit", "per-bank", "queue isolation",
            "transaction expired", "polling fallback", "circuit breaker", "co lap",
        ],
        "rationale": "In the synchronous BC path a slow bank fills the shared consume queue and stalls healthy banks, producing -9205 INTERNAL_BC_TIME_OUT and cascading restarts. New connector calls should use the async V3.1 flow with per-bank rate limiting and a transaction-expired message to isolate slow banks.",
    },
    {
        # Phụ thuộc 1 ngân hàng/luồng QR mà không có failover (VPB 2026-01:
        # switch IBFT scenario + chuyển VietQR Động sang Bản Việt).
        "title": "Single-bank or single-QR-route dependency lacks a maintenance/failover path.",
        "severity": RiskLevel.HIGH,
        "category": "Bank Connector",
        "requires_any": [
            "single bank", "vietqr dong", "qr dong", "ibft scenario", "one bank",
            "phu thuoc mot ngan hang", "duy nhat mot ngan hang", "primary bank",
        ],
        "missing_all": [
            "failover", "switch bank", "alternate bank", "maintenance scenario",
            "bam object", "automatic maintenance", "ban viet", "du phong", "chuyen luong",
        ],
        "rationale": "When a payment route depends on a single bank with no alternate, an outage takes the whole flow down (VPB 2026-01: IBFT pending with -5007). Releases adding/altering a bank route need a maintenance scenario and a documented failover (BAM object + switch to an alternate bank/QR provider).",
    },
]


def _has_any(text: str, terms: list[str]) -> bool:
    return any(re.search(rf"\b{re.escape(term)}\b", text) for term in terms)


def _has_none(text: str, terms: list[str]) -> bool:
    return not _has_any(text, terms)


def score_domain_baseline(domains: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for domain in domains:
        if domain in CRITICAL_DOMAINS:
            findings.append(
                Finding(
                    title=f"{domain.replace('_', ' ').title()} requires P0 payment integrity coverage.",
                    severity=RiskLevel.HIGH,
                    category="Domain impact",
                    rationale="The changed area can affect customer funds, ledger consistency, partner settlement, or production reconciliation.",
                )
            )
        elif domain in HIGH_DOMAINS:
            findings.append(
                Finding(
                    title=f"{domain.replace('_', ' ').title()} requires security and integration coverage.",
                    severity=RiskLevel.MEDIUM,
                    category="Domain impact",
                    rationale="The changed area can affect authentication, fraud exposure, partner contracts, or account access.",
                )
            )
    return findings


def detect_risks(message: str, domains: list[str], detected_input_types: list[str]) -> list[Finding]:
    text = normalize_vietnamese_text(message.lower())
    findings = score_domain_baseline(domains)

    for rule in RISK_RULES:
        requires_all = rule.get("requires_all", [])
        requires_any_context = rule.get("requires_any_context", [])
        if (
            _has_any(text, rule["requires_any"])
            and (not requires_any_context or _has_any(text, requires_any_context))
            and all(needle in text for needle in requires_all)
            and _has_none(text, rule["missing_all"])
        ):
            findings.append(
                Finding(
                    title=rule["title"],
                    severity=rule["severity"],
                    category=rule["category"],
                    rationale=rule["rationale"],
                )
            )

    if "impact_analysis_doc" in detected_input_types and "git_diff" in detected_input_types:
        declared_refund_only = bool(re.search(r"(?i)(refund only|only refund|scope\s*:\s*refund)", message))
        diff_implies_ledger = bool(re.search(r"(?m)^diff --git .*?(ledger|journal|schema|migration|settlement|recon)", message, re.I))
        if declared_refund_only and diff_implies_ledger:
            findings.append(
                Finding(
                    title="Declared impact does not match code/config footprint.",
                    severity=RiskLevel.CRITICAL,
                    category="Cross-check",
                    rationale="Impact text narrows scope to refund, but diff indicates ledger/schema/settlement surface that needs reconciliation and rollback testing.",
                )
            )

    unique: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        unique[(finding.title, finding.category)] = finding
    return list(unique.values())


def overall_risk(findings: list[Finding]) -> RiskLevel:
    if any(item.severity == RiskLevel.CRITICAL for item in findings):
        return RiskLevel.CRITICAL
    if any(item.severity == RiskLevel.HIGH for item in findings):
        return RiskLevel.HIGH
    if any(item.severity == RiskLevel.MEDIUM for item in findings):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
