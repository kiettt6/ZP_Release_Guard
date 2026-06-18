import os
import re
from collections import Counter

from zp_release_guard import llm_client
from zp_release_guard.language import clean_latex_symbols, response_language_for
from zp_release_guard.models import Finding, Recommendation, ReleaseContext, RiskLevel
from zp_release_guard.security import neutralize_markdown_injection


REQUIRED_SECTIONS = [
    "QA Review Summary",
    "Confirmed Impact",
    "DEV Impact Template Coverage",
    "QE Add-on Assessment",
    "Potential Missing Impact",
    "P0 Smoke Checklist",
    "P1/P2 Regression Pack",
    "Questions for Dev",
    "Risk Matrix",
    "QA Recommendation",
    "Jira/PR Comment",
]

VIETNAMESE_REQUIRED_SECTIONS = [
    "Tóm tắt QA",
    "Ảnh hưởng đã xác nhận",
    "Coverage theo template Impact Analysis của DEV",
    "Đánh giá bổ sung từ QE",
    "Ảnh hưởng có thể bị bỏ sót",
    "Checklist Smoke P0",
    "Gói Regression P1/P2",
    "Câu hỏi cho Dev",
    "Ma trận rủi ro",
    "Khuyến nghị QA",
    "Comment Jira/PR",
]

SECTION_LABELS = {
    "Vietnamese": {
        "QA Review Summary": "Tóm tắt QA",
        "Confirmed Impact": "Ảnh hưởng đã xác nhận",
        "DEV Impact Template Coverage": "Coverage theo template Impact Analysis của DEV",
        "QE Add-on Assessment": "Đánh giá bổ sung từ QE",
        "Potential Missing Impact": "Ảnh hưởng có thể bị bỏ sót",
        "P0 Smoke Checklist": "Checklist Smoke P0",
        "P1/P2 Regression Pack": "Gói Regression P1/P2",
        "Questions for Dev": "Câu hỏi cho Dev",
        "Risk Matrix": "Ma trận rủi ro",
        "QA Recommendation": "Khuyến nghị QA",
        "Jira/PR Comment": "Comment Jira/PR",
    }
}

DOMAIN_LABELS_VI = {
    "app_compatibility": "Tương thích app",
    "bank_linking": "Liên kết ngân hàng",
    "card_tokenization": "Token hóa thẻ",
    "cashback_reward": "Cashback và reward",
    "general_release_change": "Thay đổi release chung",
    "kyc_account_status": "KYC và trạng thái tài khoản",
    "ledger_audit_log": "Ledger và audit log",
    "merchant_payment": "Thanh toán merchant",
    "notification": "Thông báo",
    "payment": "Thanh toán",
    "refund": "Hoàn tiền",
    "risk_fraud": "Risk và fraud",
    "settlement_reconciliation": "Settlement và reconciliation",
    "top_up": "Nạp tiền",
    "transfer": "Chuyển tiền",
    "voucher_promotion": "Voucher và khuyến mãi",
    "wallet_balance": "Số dư ví",
    "tap2pay_card_processing": "Tap2Pay và xử lý thẻ quốc tế",
    "installment_paylater": "Trả góp và PayLater",
    "agreement_autopay": "Agreement Pay và autopay",
    "bank_connector": "Bank Connector và VietQR",
    "bus_ticketing_travel": "Vé xe và du lịch",
    "mobile_release_regression": "Mobile release và regression",
    "user_management": "User Management (UM)",
}

FINDING_TRANSLATIONS = {
    "Missing idempotency coverage for retryable money movement.": "Thiếu coverage idempotency cho luồng tiền có retry.",
    "Ledger and reconciliation impact is not explicitly covered.": "Ảnh hưởng ledger và reconciliation chưa được cover rõ.",
    "Refund state transition and compensation rules need QA sign-off.": "State transition và compensation của refund cần QA sign-off.",
    "Financial amount precision and rounding rules are not stated.": "Chưa nêu rõ precision và rounding cho số tiền.",
    "Refund minimum-amount threshold change needs boundary and reconciliation coverage.": "Thay đổi ngưỡng số tiền tối thiểu cho refund cần cover boundary và reconciliation.",
    "Token/session security controls are not visible.": "Chưa thấy rõ security control cho token/session.",
    "Promotion abuse and duplicate claim controls are missing.": "Thiếu control chống abuse promotion và duplicate claim.",
    "Old app compatibility and rollback behavior are unclear.": "Chưa rõ tương thích app cũ và rollback behavior.",
    "Monitoring and audit evidence are not described.": "Chưa mô tả monitoring và audit evidence.",
    "Declared impact does not match code/config footprint.": "Impact khai báo không khớp footprint code/config.",
    "Settlement file or delivery config change lacks maker-checker and merchant verification.": "Thay đổi file settlement hoặc delivery config thiếu maker-checker và xác nhận từ merchant.",
    "Callback/DTO field change lacks backward compatibility and contract test coverage.": "Thay đổi field callback/DTO thiếu backward compatibility và contract test.",
    "Refactored or long-lived code may ride along on this release without scope review.": "Code refactor hoặc nằm lâu trên main có thể đi kèm release này mà chưa được review scope.",
    "Replay/repush/backfill operation lacks an idempotency or double-payout guard.": "Thao tác replay/repush/backfill thiếu idempotency guard chống double-payout.",
    "External dependency added or changed without failover or circuit breaker.": "Thêm/đổi dependency bên ngoài mà không có failover hoặc circuit breaker.",
    "Multi-service or shared-library release lacks an explicit deployment order.": "Release nhiều service hoặc shared-lib thiếu thứ tự deploy rõ ràng.",
    "Message consumer or merchant notification change lacks negative-path test and DLQ handling.": "Thay đổi consumer/notification merchant thiếu test nhánh lỗi và xử lý DLQ.",
    "Data restore from backup lacks post-restore validation.": "Restore dữ liệu từ backup thiếu bước validate sau khi restore.",
    "Visa/Tap2Pay MTI processing change lacks exactly-once and advice-dedup guarantees.": "Thay đổi xử lý MTI Visa/Tap2Pay thiếu đảm bảo exactly-once và chống double advice.",
    "Unbounded resource creation (dynamic topics, goroutines, connections) lacks load testing and limits.": "Tạo resource không giới hạn (dynamic topic, goroutine, connection) thiếu load test và resource limit.",
    "Reset PIN / balance liquidation flow change lacks risk, MFA, or KBA gating.": "Thay đổi luồng reset PIN / thanh lý số dư thiếu gate risk, MFA hoặc KBA.",
    "OTP send endpoint change lacks anti-spam and abuse controls.": "Thay đổi endpoint gửi OTP thiếu control chống spam và abuse.",
    "Strict parsing of upstream profile/vendor response without lenient fallback.": "Parsing strict response từ upstream/vendor mà không có fallback khoan dung.",
    "eKYC OCR/DR-rule blocking change lacks bypass, kill switch, or unknown-code fallback.": "Thay đổi chặn eKYC OCR theo DR rule thiếu bypass, kill switch hoặc fallback cho mã lạ.",
    "Backend decision-flow enum change without client mapping test and default case.": "Đổi enum decision-flow backend mà không có test mapping client và default case.",
    "CE/out-app ticket creation change lacks pending-ticket duplicate check.": "Thay đổi tạo ticket CE/out-app thiếu bước check ticket pending để chống trùng.",
    "An authentication or risk gate is being removed or weakened.": "Một gate xác thực hoặc risk đang bị gỡ bỏ hoặc làm yếu.",
    "Git diff touches money-critical files without reconciliation or rollback coverage.": "Git diff đụng vào file ảnh hưởng tiền mà không có coverage reconciliation hoặc rollback.",
    "Git diff removes a protection (idempotency, auth, or risk gate) without a visible replacement.": "Git diff gỡ bỏ một lớp bảo vệ (idempotency, auth hoặc risk gate) mà không thấy thay thế.",
}

RATIONALE_TRANSLATIONS = {
    "Retryable payment/refund paths can double debit, double refund, or emit duplicate callbacks without a stable idempotency contract.": "Luồng payment/refund có retry có thể double debit, double refund hoặc emit duplicate callback nếu không có contract idempotency ổn định.",
    "Ledger or balance changes need debit-credit consistency, settlement matching, and auditable rollback validation.": "Thay đổi ledger hoặc balance cần kiểm tra debit-credit consistency, settlement matching và rollback có audit được.",
    "Refund flows often fail in partial success and partner-timeout states unless state transitions and compensation paths are tested.": "Refund flow thường lỗi ở trạng thái partial success và partner timeout nếu state transition và compensation path chưa được test.",
    "Payment math needs deterministic decimal handling across fees, discounts, cashback, and displayed versus ledger amounts.": "Financial math cần xử lý decimal deterministic cho fee, discount, cashback và chênh lệch giữa amount hiển thị với ledger.",
    "Allowing refunds below a previous money threshold can bypass amount validation, fee/reversal rules, partner settlement assumptions, or ledger reconciliation if boundary cases are not tested.": "Cho phép refund dưới ngưỡng tiền trước đó có thể bypass validate amount, rule fee/reversal, giả định settlement với partner hoặc reconciliation ledger nếu không test boundary.",
    "Bank/card/token changes must validate storage, masking, expiry, rotation, replay prevention, and OWASP API controls.": "Thay đổi bank/card/token phải validate storage, masking, expiry, rotation, replay prevention và OWASP API controls.",
    "Campaign changes need duplicate claim, quota, velocity, and refund-after-reward abuse coverage.": "Thay đổi campaign cần cover duplicate claim, quota, velocity và abuse refund-after-reward.",
    "Mobile releases may remain mixed-version for weeks, so API response and feature flag fallback need explicit validation.": "Mobile release có thể mixed-version nhiều tuần, nên API response và feature flag fallback cần validation rõ.",
    "Production payment releases need audit logs, traceability, and alert thresholds for early rollback decisions.": "Payment release production cần audit log, traceability và alert threshold để quyết định rollback sớm.",
    "Impact text narrows scope to refund, but diff indicates ledger/schema/settlement surface that needs reconciliation and rollback testing.": "Impact text giới hạn scope ở refund, nhưng diff cho thấy surface ledger/schema/settlement cần test reconciliation và rollback.",
    "The changed area can affect customer funds, ledger consistency, partner settlement, or production reconciliation.": "Khu vực thay đổi có thể ảnh hưởng tiền khách hàng, ledger consistency, partner settlement hoặc reconciliation production.",
    "The changed area can affect authentication, fraud exposure, partner contracts, or account access.": "Khu vực thay đổi có thể ảnh hưởng authentication, fraud exposure, partner contract hoặc account access.",
    "Settlement file format, schedule, or delivery-config changes have repeatedly broken partner reconciliation (e.g. files delivered to a test folder for days). They need maker-checker approval, merchant-side confirmation, and delivery monitoring.": "Thay đổi format, lịch hoặc delivery config của file settlement đã nhiều lần làm gãy đối soát với partner (vd: file bị đẩy vào folder test nhiều ngày). Cần maker-checker, xác nhận từ merchant và monitoring delivery.",
    "Partner callback fields have been silently dropped or renamed across DTO chains (shared-lib, receiver, API), breaking old integrations or losing data with no alert. Field changes need contract tests and explicit backward compatibility.": "Field trong callback của partner từng bị drop hoặc đổi tên âm thầm qua chuỗi DTO (shared-lib, receiver, API), làm gãy tích hợp cũ hoặc mất dữ liệu mà không có alert. Thay đổi field cần contract test và backward compatibility rõ ràng.",
    "Untested refactors merged to main months earlier have shipped accidentally alongside unrelated deploys and caused fund loss. Release notes must confirm a git-diff review between the production version and the deploy candidate.": "Refactor chưa test merge vào main từ nhiều tháng trước từng bị deploy kèm thay đổi không liên quan và gây mất tiền. Release note phải confirm đã review git diff giữa version production và bản deploy.",
    "Recovery via Kafka replay, file repush, or data backfill risks double-processing and double payout unless every replayed item is idempotent and verified against already-settled records.": "Recovery bằng replay Kafka, repush file hoặc backfill dữ liệu có nguy cơ xử lý trùng và double payout nếu từng item replay không idempotent và không đối chiếu với bản ghi đã settle.",
    "Bank/Napas outages and third-party CDN failures are survivable only with multi-bank routing, fallback, or self-hosted assets. Single external dependencies without failover degrade payment availability.": "Sự cố ngân hàng/Napas và CDN bên thứ ba chỉ vượt qua được nhờ routing đa ngân hàng, fallback hoặc self-host. Dependency ngoài đơn lẻ không có failover làm giảm availability thanh toán.",
    "Releases spanning shared libraries and multiple dependent services break when components ship out of order. The rollout checklist must state the exact deployment sequence and a staging verification step.": "Release trải qua shared-lib và nhiều service phụ thuộc sẽ gãy nếu deploy sai thứ tự. Rollout checklist phải nêu rõ thứ tự deploy và bước verify trên staging.",
    "An early return on the pending/error branch of a consumer dropped merchant payment notifications right after release. Consumer changes need pending/failed-path tests, retry or DLQ handling, and a missing-message alert.": "Một lệnh early return ở nhánh pending/error của consumer từng làm rớt notification thanh toán cho merchant ngay sau release. Thay đổi consumer cần test nhánh pending/failed, retry hoặc DLQ, và alert khi thiếu message.",
    "A backup restore has silently truncated stored values and broken lookups (AppNotFound). Every restore needs post-restore validation: checksums, sample verification, and cross-system comparison.": "Một lần restore backup từng làm truncate dữ liệu âm thầm và gãy lookup (AppNotFound). Mọi lần restore cần validate sau restore: checksum, verify mẫu và so sánh chéo hệ thống.",
    "Visa requires exactly-once processing per MTI 0x00 request and at most one advice (0x20) adjustment per payment, with retries on the same bcTransID. Changes here without these guarantees cause double debit or unmatched clearing.": "Visa yêu cầu xử lý exactly-once cho mỗi request MTI 0x00 và tối đa một advice (0x20) điều chỉnh trên mỗi payment, retry trên cùng bcTransID. Thay đổi ở đây mà thiếu các đảm bảo này sẽ gây double debit hoặc lệch clearing.",
    "Dynamically created Kafka topics once took the shared cluster down, and a goroutine leak exhausted RAM/CPU into restart loops. New per-request resource creation needs hard limits and a load test.": "Kafka topic tạo động từng làm sập cluster dùng chung, goroutine leak từng làm cạn RAM/CPU gây restart loop. Resource tạo theo request cần hard limit và load test.",
    "Reset-PIN and balance-liquidation flows are gated by risk level (auto / RBA-MFA / manual owner flow), KBA blocking after failed attempts, and face authentication on untrusted devices. Removing or weakening any gate opens account takeover and fund-out risk.": "Luồng reset PIN và thanh lý số dư được gate theo risk level (auto / RBA-MFA / owner flow thủ công), KBA block khi sai quá số lần và face authen trên thiết bị không trust. Bỏ hoặc làm yếu bất kỳ gate nào sẽ mở rủi ro chiếm tài khoản và fund-out.",
    "OTP send endpoints have been abused in production for phone enumeration and SMS-OTP spam (replayed send_otp_token). Changes need per-phone/IP rate limits, a risk-engine checkpoint before sending, and captcha when spam is suspected.": "Endpoint gửi OTP từng bị abuse trên production để dò số điện thoại và spam SMS OTP (replay send_otp_token). Thay đổi cần rate limit theo phone/IP, checkpoint risk engine trước khi gửi và captcha khi nghi spam.",
    "An upstream provider silently removing a profile field once broke login for ~52k requests/hour because parsing was strict. Upstream and eKYC vendor responses (TrueID, JTH, BCA) need lenient parsing, optional fields, and vendor fallback chains.": "Một upstream từng âm thầm bỏ field profile làm gãy login ~52k request/giờ vì parsing strict. Response từ upstream và vendor eKYC (TrueID, JTH, BCA) cần lenient parsing, field optional và fallback chain giữa vendor.",
    "Blocking eKYC OCR submission on DR rules is only safe with a three-strike backend bypass, an A/B kill switch, and unknown-reason-code no-op fallback for old apps. The OCR submit flow has no unit-test coverage, so manual validation is mandatory.": "Chặn submit OCR eKYC theo DR rule chỉ an toàn khi có three-strike bypass phía backend, kill switch A/B và fallback no-op cho reason code lạ trên app cũ. Flow OCR submit không có unit test nên bắt buộc validate thủ công.",
    "Backend decision-flow enums (e.g. DF_TYPE_NFC_VERIFICATION with reasons NFC_PROCESSING/NEW_USER/FUND_OUT_LIMIT/BLACKLIST) drive client UI routing at fund-out time. New or renumbered values without a client default case misroute users.": "Enum decision-flow của backend (vd DF_TYPE_NFC_VERIFICATION với reason NFC_PROCESSING/NEW_USER/FUND_OUT_LIMIT/BLACKLIST) điều khiển trực tiếp điều hướng UI client tại thời điểm fund-out. Thêm hoặc đánh số lại enum mà client không có default case sẽ điều hướng sai user.",
    "The app previously created duplicate CE support tickets because it never pre-checked pending tickets. Ticket-creation flows must search by the same request_type and pending-group statuses before creating a new one.": "App từng tạo trùng ticket hỗ trợ CE vì không pre-check ticket pending. Luồng tạo ticket phải search theo cùng request_type và nhóm status pending trước khi tạo mới.",
    "The release explicitly removes or weakens an authentication/risk gate (KBA, OTP, MFA, face authen, risk check) in a flow that protects account access or fund-out. This requires an explicit security review and a documented compensating control.": "Release này gỡ bỏ hoặc làm yếu một gate xác thực/risk (KBA, OTP, MFA, face authen, risk check) trong luồng bảo vệ tài khoản hoặc fund-out. Bắt buộc phải có security review và compensating control được document rõ.",
    "The diff changes ledger/schema/settlement files that affect fund integrity, but the change description states no reconciliation, backfill, or rollback plan for them.": "Diff thay đổi các file ledger/schema/settlement ảnh hưởng tính toàn vẹn của tiền, nhưng mô tả thay đổi không nêu plan reconciliation, backfill hoặc rollback cho chúng.",
    "A guard present on removed lines does not appear on added lines, so the diff weakens a control protecting fund-out or account access. Confirm an equivalent control remains and add a regression test.": "Một guard xuất hiện ở dòng bị xóa nhưng không có ở dòng thêm vào, nên diff làm yếu một control bảo vệ fund-out hoặc account access. Cần confirm vẫn còn control tương đương và bổ sung regression test.",
}

CHECK_TRANSLATIONS = {
    "Validate request idempotency for retry, timeout, and duplicate callback paths.": "Validate request idempotency cho các path retry, timeout và duplicate callback.",
    "Verify debit-credit ledger entries remain balanced for successful, failed, and reversed transactions.": "Verify debit-credit ledger entries vẫn balanced cho transaction success, failed và reversed.",
    "Run rollback or compensation scenario and confirm customer-visible balance is restored.": "Chạy rollback hoặc compensation scenario và confirm balance hiển thị cho user được restore.",
    "Check audit logs, trace ids, and monitoring alerts for each money movement state.": "Kiểm tra audit log, trace id và monitoring alert cho từng trạng thái money movement.",
    "Execute full, partial, duplicate, and partner-timeout refund smoke tests.": "Chạy smoke test refund full, partial, duplicate và partner-timeout.",
    "Validate refund amount boundaries at 1,999 VND, 2,000 VND, and 2,001 VND for NAPAS transactions.": "Validate boundary amount refund cho giao dịch NAPAS tại 1,999 VND, 2,000 VND và 2,001 VND.",
    "Verify the refund ledger/reconciliation amount equals the original transaction amount without fee or rounding drift.": "Verify amount trên ledger/reconciliation của refund khớp original transaction amount, không lệch do fee hoặc rounding.",
    "Validate duplicate claim, quota, abuse, refund-after-reward, and campaign expiry handling.": "Validate duplicate claim, quota, abuse, refund-after-reward và campaign expiry handling.",
    "Validate token masking, expiry, replay prevention, unlink/relink, and old app behavior.": "Validate token masking, expiry, replay prevention, unlink/relink và behavior trên app cũ.",
    "Review diff footprint with dev lead and expand sign-off scope to ledger/schema/reconciliation.": "Review diff footprint với dev lead và mở rộng scope sign-off sang ledger/schema/reconciliation.",
    "P1 Integration: partner callback ordering, timeout, retry backoff, and reconciliation file consistency.": "P1 Integration: partner callback ordering, timeout, retry backoff và reconciliation file consistency.",
    "P1 Security: authorization boundaries, token redaction, replay protection, and OWASP API negative tests.": "P1 Security: authorization boundary, token redaction, replay protection và OWASP API negative test.",
    "P2 Observability: dashboard, alert threshold, structured logs, and audit export validation.": "P2 Observability: dashboard, alert threshold, structured log và audit export validation.",
    "P1 Compatibility: old Android/iOS app contract, feature flag fallback, and mixed-version rollout.": "P1 Compatibility: contract app Android/iOS cũ, feature flag fallback và mixed-version rollout.",
    "P1 Reconciliation: settlement mismatch, rounding delta, duplicate journal, and backfill migration checks.": "P1 Reconciliation: settlement mismatch, rounding delta, duplicate journal và backfill migration check.",
    "What is the idempotency key source, retention window, and duplicate response contract?": "Nguồn idempotency key, retention window và duplicate response contract là gì?",
    "Which ledger, settlement, and reconciliation tables or jobs are changed or backfilled?": "Bảng/job ledger, settlement và reconciliation nào bị thay đổi hoặc backfill?",
    "How are tokens stored, masked, expired, rotated, and protected from replay?": "Token được store, mask, expire, rotate và chống replay như thế nào?",
    "What fraud, velocity, quota, and duplicate-claim controls are enforced server-side?": "Server-side enforce fraud, velocity, quota và duplicate-claim control nào?",
    "What old app versions remain supported and what is the rollback or feature flag path?": "Version app cũ nào còn được support và rollback/feature flag path là gì?",
    "Can dev confirm no money movement, ledger, token, or reconciliation behavior changed?": "Dev có thể confirm không có thay đổi money movement, ledger, token hoặc reconciliation behavior không?",
}

RECOMMENDATION_REASON_TRANSLATIONS = {
    "block release until P0 integrity gaps are addressed and re-tested.": "block release cho đến khi các điểm thiếu P0 integrity được xử lý và re-test.",
    "release only after listed P0 checks and owner sign-off are completed.": "chỉ release sau khi hoàn tất P0 checks đã liệt kê và owner sign-off.",
    "acceptable with targeted regression coverage and monitoring readiness.": "có thể chấp nhận nếu có targeted regression coverage và monitoring readiness.",
    "no material payment risk detected from the provided input.": "không phát hiện material payment risk từ input được cung cấp.",
}


def _is_vietnamese(language: str) -> bool:
    return language == "Vietnamese"


def recommendation_for(risk_level: RiskLevel, findings: list[Finding]) -> Recommendation:
    if risk_level == RiskLevel.CRITICAL:
        return Recommendation.NO_GO
    if risk_level == RiskLevel.HIGH or len(findings) >= 4:
        return Recommendation.CONDITIONAL_GO
    return Recommendation.GO


def _t(text: str, language: str) -> str:
    if not _is_vietnamese(language):
        return text
    return CHECK_TRANSLATIONS.get(
        text,
        RATIONALE_TRANSLATIONS.get(
            text,
            FINDING_TRANSLATIONS.get(
                text,
                RECOMMENDATION_REASON_TRANSLATIONS.get(text, text),
            ),
        ),
    )


def _bullet(items: list[str], language: str = "English") -> str:
    if items:
        return "\n".join(f"- {_t(item, language)}" for item in items)
    if _is_vietnamese(language):
        return "- Không phát hiện từ input được cung cấp."
    return "- None detected from provided input."


def _section(name: str, language: str) -> str:
    return SECTION_LABELS.get(language, {}).get(name, name)


def _domain_label(domain: str, language: str = "English") -> str:
    if _is_vietnamese(language):
        return DOMAIN_LABELS_VI.get(domain, domain.replace("_", " "))
    return domain.replace("_", " ").title()


def _safe_inline(text: str | None, fallback: str) -> str:
    if not text:
        return fallback
    return neutralize_markdown_injection(text).replace("\n", " ").strip() or fallback


def _finding_text(item: Finding, language: str) -> str:
    title = _t(item.title, language)
    rationale = _t(item.rationale, language)
    # In đậm các impact mức Critical/High để user chú ý ngay vào nội dung đặc biệt.
    if item.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return f"**[{item.severity.value}] {title}** {rationale}"
    return f"{title} {rationale}"


def _user_intent_summary(context: ReleaseContext, findings: list[Finding], language: str) -> str:
    raw = neutralize_markdown_injection(context.raw_message).replace("\n", " ").strip()
    lowered = raw.lower()
    has_refund_threshold = (
        "refund" in lowered
        and "vnd" in lowered
        and ("below" in lowered or "under" in lowered or "duoi" in lowered or "dưới" in lowered)
        and ("2,000" in lowered or "2000" in lowered or "2.000" in lowered)
    )
    has_threshold_finding = any(
        item.title == "Refund minimum-amount threshold change needs boundary and reconciliation coverage."
        for item in findings
    )

    if has_refund_threshold or has_threshold_finding:
        if _is_vietnamese(language):
            return _bullet(
                [
                    "Tôi hiểu yêu cầu là đổi business rule để cho phép refund các giao dịch NAPAS có amount dưới 2,000 VND, tức chạm trực tiếp vào min-amount validation của refund.",
                    "Trọng tâm QA là refund eligibility, boundary amount, ledger amount, partner settlement/reconciliation và rollback nếu rule mới gây lệch tiền.",
                    "Các mốc cần test rõ: 1,999 VND được refund, 2,000 VND vẫn pass, 2,001 VND không bị regression, amount lẻ/rounding nếu có fee hoặc partial refund.",
                ],
                language,
            )
        return _bullet(
            [
                "I interpret the request as a business-rule change that allows NAPAS transaction refunds below 2,000 VND, directly touching refund minimum-amount validation.",
                "The QA focus is refund eligibility, amount boundaries, ledger amount, partner settlement/reconciliation, and rollback if the new rule creates money mismatch.",
                "Boundary tests should cover 1,999 VND accepted, 2,000 VND still accepted, 2,001 VND not regressed, plus decimal/rounding behavior for fee or partial-refund paths.",
            ],
            language,
        )

    if _is_vietnamese(language):
        return _bullet(
            [
                f"Tôi hiểu input là thay đổi ở scope {', '.join(_domain_label(domain, language) for domain in context.domain_signals)}.",
                "Vì mô tả còn ngắn, report ưu tiên nêu giả định, rủi ro cần xác nhận và checklist P0 để dev bổ sung evidence.",
            ],
            language,
        )
    return _bullet(
        [
            f"I interpret the input as a change in {', '.join(_domain_label(domain, language) for domain in context.domain_signals)} scope.",
            "Because the description is short, the report focuses on assumptions, risks to confirm, and P0 evidence dev should provide.",
        ],
        language,
    )


def _dev_template_coverage(
    context: ReleaseContext,
    findings: list[Finding],
    risk_level: RiskLevel,
    language: str,
) -> str:
    if _is_vietnamese(language):
        return f"""### 1. Overview / Tổng quan
- Feature/Ticket ID: Chưa xác định từ input. Cần dev cung cấp Jira/Ticket link nếu chưa có.
- Scope of Change: {", ".join(_domain_label(domain, language) for domain in context.domain_signals)}
- Types of Changes: Suy luận từ input: {", ".join(context.input_sources)}
- Tech Document / PRD: Chưa xác định từ input. Cần link PRD/tech document nếu release có thay đổi logic/API/database.
- Summary: Review tập trung vào impact payment integrity, ledger/reconciliation, idempotency, security, rollback và monitoring.

### 2. Technical Impact / Tác động kỹ thuật
- Affected Components: {", ".join(_domain_label(domain, language) for domain in context.domain_signals)}
- External Impact: Cần xác nhận client/domain phụ thuộc, partner callback, API consumer, message/state machine nếu có.
- Performance Impact: Cần estimate CPU, memory, database/Redis throughput, query scan, API latency delta.
- Breaking Changes: Cần xác nhận thay đổi database, API data contract, SLA/rate limit/circuit breaker, fund flow, deprecate version/logic/data.

### 3. Risk Product Assessment / Đánh giá rủi ro
- Risk Level: {risk_level.value}
- Side Effects: {len(findings)} finding cần review trước production, đặc biệt các luồng không trực tiếp nhưng có thể ảnh hưởng tiền, ledger, reconciliation hoặc báo cáo.
- Security Impact: Cần confirm đã check security nếu có token/session/bank/card/API authorization.

### 4. Verification & Testing / Xác thực và kiểm thử
- Unit / Integration Tests: Cần dev nêu coverage tăng/giảm, test chính và trạng thái pass/fail.
- Manual Testing: QE cần cover P0 smoke checklist và các regression pack bên dưới.
- Edge Cases: Cần cover timeout, retry, duplicate request/callback, null data, old app, offline/recovery, partner unavailable.

### 5. Rollback & Monitoring / Thu hồi và giám sát
- Deployment Plan: Cần rõ rollout plan, feature flag/canary, config DB/CMDB, thứ tự build nếu nhiều service.
- Rollback Plan: Cần mô tả cách quay lại trạng thái cũ và compensation nếu có money movement.
- Monitoring: Cần theo dõi error rate, latency, audit log, trace id, reconciliation delta, alert threshold.
- Additional Checks: Cân nhắc monitoring 24/7 và phối hợp OP/Biz/Merchant nếu ảnh hưởng giao dịch khách hàng."""

    return f"""### 1. Overview
- Feature/Ticket ID: Not detected from input. Dev should provide Jira/Ticket link if missing.
- Scope of Change: {", ".join(_domain_label(domain, language) for domain in context.domain_signals)}
- Types of Changes: Inferred inputs: {", ".join(context.input_sources)}
- Tech Document / PRD: Not detected from input. Required when logic/API/database behavior changes.
- Summary: Review focuses on payment integrity, ledger/reconciliation, idempotency, security, rollback, and monitoring impact.

### 2. Technical Impact
- Affected Components: {", ".join(_domain_label(domain, language) for domain in context.domain_signals)}
- External Impact: Confirm dependent clients/domains, partner callbacks, API consumers, message/state-machine contracts.
- Performance Impact: Estimate CPU, memory, database/Redis throughput, query scan risk, and API latency delta.
- Breaking Changes: Confirm database, API data contract, SLA/rate limit/circuit breaker, fund flow, and deprecated version/logic/data changes.

### 3. Risk Product Assessment
- Risk Level: {risk_level.value}
- Side Effects: {len(findings)} findings require review before production, especially indirect impact to funds, ledger, reconciliation, or reporting.
- Security Impact: Confirm security review for token/session/bank/card/API authorization surfaces.

### 4. Verification & Testing
- Unit / Integration Tests: Dev should state coverage delta, key tests, and pass/fail status.
- Manual Testing: QE should execute the P0 smoke checklist and regression pack below.
- Edge Cases: Cover timeout, retry, duplicate request/callback, null data, old app, offline/recovery, and partner unavailable states.

### 5. Rollback & Monitoring
- Deployment Plan: Clarify rollout plan, feature flag/canary, DB/CMDB config, and build order for multi-service releases.
- Rollback Plan: Describe fastest recovery path and compensation if money movement is involved.
- Monitoring: Track error rate, latency, audit log, trace id, reconciliation delta, and alert thresholds.
- Additional Checks: Consider 24/7 monitoring and OP/Biz/Merchant coordination for customer-transaction impact."""


def _qe_add_on_assessment(domains: list[str], findings: list[Finding], language: str) -> str:
    if _is_vietnamese(language):
        return """- QE Release Gate: Không sign-off nếu còn điểm thiếu P0 về idempotency, ledger balance, rollback/compensation, token security hoặc monitoring.
- P0 Manual/Exploratory: Validate happy path, failed path, timeout/retry, duplicate request/callback, partial success và recovery/offline state.
- Data Integrity: Kiểm tra customer-visible balance, debit-credit ledger, settlement/reconciliation delta, audit trail và idempotency key uniqueness.
- Security/Compliance: Kiểm tra authorization boundary, token masking/encryption/expiry, replay prevention, PII/secret redaction và OWASP API negative cases.
- Performance/Operability: Theo dõi latency p95/p99, throughput, DB/Redis query cost, CPU/memory, alert threshold và rollback drill.
- Evidence Required: Cần log/test evidence cho P0 checklist, regression result, monitoring dashboard và owner sign-off trước production."""

    return """- QE Release Gate: Do not sign off while P0 gaps remain for idempotency, ledger balance, rollback/compensation, token security, or monitoring.
- P0 Manual/Exploratory: Validate happy path, failed path, timeout/retry, duplicate request/callback, partial success, and recovery/offline states.
- Data Integrity: Check customer-visible balance, debit-credit ledger, settlement/reconciliation delta, audit trail, and idempotency key uniqueness.
- Security/Compliance: Check authorization boundaries, token masking/encryption/expiry, replay prevention, PII/secret redaction, and OWASP API negative cases.
- Performance/Operability: Monitor p95/p99 latency, throughput, DB/Redis query cost, CPU/memory, alert thresholds, and rollback drill.
- Evidence Required: Attach logs/test evidence for P0 checklist, regression result, monitoring dashboard, and owner sign-off before production."""


def render_markdown_report(
    context: ReleaseContext,
    findings: list[Finding],
    risk_level: RiskLevel,
    recommendation: Recommendation,
    language: str = "English",
) -> str:
    severity_count = Counter(item.severity.value for item in findings)
    confirmed = [_domain_label(domain, language) for domain in context.domain_signals]
    missing = [_finding_text(item, language) for item in findings]
    p0_checks = _p0_smoke_checks(context.domain_signals, findings)
    regression = _regression_pack(context.domain_signals, findings)
    questions = _questions_for_dev(findings)
    if _is_vietnamese(language):
        matrix = ["| Rủi ro | Mức độ | Nhóm |", "| --- | --- | --- |"]
    else:
        matrix = ["| Risk | Severity | Category |", "| --- | --- | --- |"]
    matrix.extend(f"| {_t(item.title, language)} | {item.severity.value} | {item.category} |" for item in findings)

    evidence = _bullet([f"{item.source}: {item.snippet}" for item in context.evidence[:6]])
    intent_summary = _user_intent_summary(context, findings, language)
    project = _safe_inline(context.project_hint, "zalopay")
    release = _safe_inline(context.release_hint, "Không được cung cấp" if _is_vietnamese(language) else "Not specified")
    if _is_vietnamese(language):
        report = f"""## {_section("QA Review Summary", language)}
- Project: {project}
- Release: {release}
- Input phát hiện: {", ".join(context.input_sources)}
- Mức rủi ro tổng thể: {risk_level.value}
- Khuyến nghị: {recommendation.value}
- Số lượng finding: Critical={severity_count.get("Critical", 0)}, High={severity_count.get("High", 0)}, Medium={severity_count.get("Medium", 0)}, Low={severity_count.get("Low", 0)}

## {_section("Confirmed Impact", language)}
{_bullet(confirmed, language)}

Evidence đã review:
{evidence}

## Cách tôi hiểu yêu cầu
{intent_summary}

## {_section("DEV Impact Template Coverage", language)}
{_dev_template_coverage(context, findings, risk_level, language)}

## {_section("QE Add-on Assessment", language)}
{_qe_add_on_assessment(context.domain_signals, findings, language)}

## {_section("Potential Missing Impact", language)}
{_bullet(missing, language)}

## {_section("P0 Smoke Checklist", language)}
{_bullet(p0_checks, language)}

## {_section("P1/P2 Regression Pack", language)}
{_bullet(regression, language)}

## {_section("Questions for Dev", language)}
{_bullet(questions, language)}

## {_section("Risk Matrix", language)}
{chr(10).join(matrix)}

## {_section("QA Recommendation", language)}
{recommendation.value}: {_t(_recommendation_reason(risk_level, findings), language)}

## {_section("Jira/PR Comment", language)}
Kết quả QA impact review: **{recommendation.value}** với risk **{risk_level.value}**.

Cần hoàn tất trước production:
{_bullet(p0_checks[:5], language)}
"""
        return report

    report = f"""## QA Review Summary
- Project: {project}
- Release: {release}
- Detected inputs: {", ".join(context.input_sources)}
- Overall risk: {risk_level.value}
- Recommendation: {recommendation.value}
- Finding count: Critical={severity_count.get("Critical", 0)}, High={severity_count.get("High", 0)}, Medium={severity_count.get("Medium", 0)}, Low={severity_count.get("Low", 0)}

## Confirmed Impact
{_bullet(confirmed, language)}

Evidence reviewed:
{evidence}

## How I Understand The Request
{intent_summary}

## DEV Impact Template Coverage
{_dev_template_coverage(context, findings, risk_level, language)}

## QE Add-on Assessment
{_qe_add_on_assessment(context.domain_signals, findings, language)}

## Potential Missing Impact
{_bullet(missing, language)}

## P0 Smoke Checklist
{_bullet(p0_checks, language)}

## P1/P2 Regression Pack
{_bullet(regression, language)}

## Questions for Dev
{_bullet(questions, language)}

## Risk Matrix
{chr(10).join(matrix)}

## QA Recommendation
{recommendation.value}: {_recommendation_reason(risk_level, findings)}

## Jira/PR Comment
QA impact review result: **{recommendation.value}** with **{risk_level.value}** risk.

Required before production:
{_bullet(p0_checks[:5], language)}
"""
    return report


def _p0_smoke_checks(domains: list[str], findings: list[Finding]) -> list[str]:
    checks = [
        "Validate request idempotency for retry, timeout, and duplicate callback paths.",
        "Verify debit-credit ledger entries remain balanced for successful, failed, and reversed transactions.",
        "Run rollback or compensation scenario and confirm customer-visible balance is restored.",
        "Check audit logs, trace ids, and monitoring alerts for each money movement state.",
    ]
    if "refund" in domains:
        checks.append("Execute full, partial, duplicate, and partner-timeout refund smoke tests.")
    if any(item.title == "Refund minimum-amount threshold change needs boundary and reconciliation coverage." for item in findings):
        checks.append("Validate refund amount boundaries at 1,999 VND, 2,000 VND, and 2,001 VND for NAPAS transactions.")
        checks.append("Verify the refund ledger/reconciliation amount equals the original transaction amount without fee or rounding drift.")
    if "voucher_promotion" in domains or "cashback_reward" in domains:
        checks.append("Validate duplicate claim, quota, abuse, refund-after-reward, and campaign expiry handling.")
    if "bank_linking" in domains or "card_tokenization" in domains:
        checks.append("Validate token masking, expiry, replay prevention, unlink/relink, and old app behavior.")
    if any(item.category == "Cross-check" for item in findings):
        checks.append("Review diff footprint with dev lead and expand sign-off scope to ledger/schema/reconciliation.")
    return checks


def _regression_pack(domains: list[str], findings: list[Finding]) -> list[str]:
    pack = [
        "P1 Integration: partner callback ordering, timeout, retry backoff, and reconciliation file consistency.",
        "P1 Security: authorization boundaries, token redaction, replay protection, and OWASP API negative tests.",
        "P2 Observability: dashboard, alert threshold, structured logs, and audit export validation.",
    ]
    if "app_compatibility" in domains or any(item.category == "Compatibility" for item in findings):
        pack.append("P1 Compatibility: old Android/iOS app contract, feature flag fallback, and mixed-version rollout.")
    if "settlement_reconciliation" in domains or "ledger_audit_log" in domains:
        pack.append("P1 Reconciliation: settlement mismatch, rounding delta, duplicate journal, and backfill migration checks.")
    return pack


def _questions_for_dev(findings: list[Finding]) -> list[str]:
    questions = []
    if any(item.category == "Idempotency" for item in findings):
        questions.append("What is the idempotency key source, retention window, and duplicate response contract?")
    if any(item.category == "Ledger" for item in findings):
        questions.append("Which ledger, settlement, and reconciliation tables or jobs are changed or backfilled?")
    if any(item.category == "Security" for item in findings):
        questions.append("How are tokens stored, masked, expired, rotated, and protected from replay?")
    if any(item.category == "Fraud" for item in findings):
        questions.append("What fraud, velocity, quota, and duplicate-claim controls are enforced server-side?")
    if any(item.category == "Compatibility" for item in findings):
        questions.append("What old app versions remain supported and what is the rollback or feature flag path?")
    return questions or ["Can dev confirm no money movement, ledger, token, or reconciliation behavior changed?"]


def _recommendation_reason(risk_level: RiskLevel, findings: list[Finding]) -> str:
    if risk_level == RiskLevel.CRITICAL:
        return "block release until P0 integrity gaps are addressed and re-tested."
    if risk_level == RiskLevel.HIGH or len(findings) >= 4:
        return "release only after listed P0 checks and owner sign-off are completed."
    if findings:
        return "acceptable with targeted regression coverage and monitoring readiness."
    return "no material payment risk detected from the provided input."


def rewrite_report_with_llm(raw_message: str, markdown_report: str) -> str:
    import sys
    if "pytest" in sys.modules:
        return markdown_report
    response_language = response_language_for(raw_message)

    rewrite_enabled = os.getenv("LLM_ENABLE_REWRITE", "").strip().lower() in {"1", "true", "yes", "on"}
    if not rewrite_enabled or not llm_client.is_configured():
        return markdown_report

    system_prompt = (
        "You are an expert payment-focused QA engineer at ZaloPay.\n"
        "You will be given a deterministic draft QA review report (generated by a rule engine) and the raw developer's release changes/notes.\n"
        "Your task is to rewrite the markdown report to make it highly specific, detailed, and customized to the actual developer's changes.\n"

        # ------------------------------------------------------------------
        # ZALOPAY BUSINESS CONTEXT
        # Nguồn: Confluence space ZTM (templates, RCA, EA docs, service list).
        # Cập nhật khi onboard partner mới hoặc sau incident production lớn.
        # ------------------------------------------------------------------
        "\nZaloPay business context:\n"

        # Luồng giao dịch cốt lõi
        "- Core transaction flows: payment (QR, VietQR, deeplink, merchant), refund, top-up (bank transfer, ATM, linked bank), "
        "P2P transfer, cashback disbursement, voucher redemption, installment/PayLater repayment, "
        "Tap2Pay (Visa issuing via Pismo), Agreement Pay/autopay, merchant settlement payout.\n"

        # Idempotency
        "- Idempotency standard: order_id / app_trans_id is the primary idempotency key for money-movement APIs "
        "(duplicate app_trans_id returns error -68). Visa/Tap2Pay rules: MTI 0x00 (0100/0200/0400) must execute "
        "exactly once per request — repeats return the previously returned state; MTI 0x20 advices (0120/0220/0420) "
        "retry on the same bcTransID; each payment/refund may be adjusted by at most ONE advice (0220); "
        "unmapped MTI/processing-code pairs must be rejected, not processed. Original-transaction lookback window: 12 months.\n"

        # Partner tích hợp
        "- Key payment partners: Domestic interbank networks (VietQR), card schemes via card processors, "
        "partner bank connectors (for installments/BNPL debt settlement), statement processing banks, "
        "merchant settlement banks (supporting batch payouts via message queues or batch API endpoints), "
        "RBA/MFA callback banks, multi-bank QR routing to mitigate provider outages, "
        "Agreement Pay merchants (supporting automated debit/payout tokens), "
        "transport/travel aggregators, and settlement-file merchants.\n"

        # Service / hệ thống nội bộ
        "- Key internal systems: TPE (payment engine), MCPF (merchant platform), bc-api / bc-bank-receiver (Bank Connector), "
        "Batch Statement Service (settlement processor + per-bank connectors), reconcile-center (SFTP/email recon files), "
        "payout-service (realtime bank payout), generate-payout (periodic payout, PMR approval), "
        "settlement-reconcile-adapter (Google/Alipay+ passive settlement), Temporal workflows + cron-service.\n"

        # Bảng DB quan trọng
        "- Critical DB tables: transactions, ledger_journal, settlement_request (PK merchant_request_id = idempotency key), "
        "batch, batch_record (ben_account, bank_ref_no, return_code), webhook_event (unique event_id), wallet_balance, "
        "refund_request, partner_callback_log. Any schema change to these tables requires reconciliation and rollback plan.\n"

        # Settlement / Reconciliation
        "- Reconciliation: Tap2Pay runs 4 segments — Transaction Recon (Visa×BC, OP, T+2), Fund Recon (BC×TPE, FA, T+2; "
        "KNOWN GAP: does not cover refunds), Bank Statement Recon (Visa×BC×STB, FA, T+2), Bundle Recon (TPE order lifecycle, FA, E+2). "
        "Refund matched to a reversal must NEVER be resubmitted (fund-loss prevention). "
        "Reversal amounts reconcile against F95.1/F61.3, never F4/F6 directly. "
        "Settlement cycles: T+0 intraday with Napas, T+1 end-of-day batch with banks. Mismatch threshold: 0 tolerance.\n"

        # Wallet balance consistency
        "- Wallet balance rule: available_balance = total_balance - hold_balance. "
        "Both fields must update atomically. Any change to balance logic must verify "
        "hold_balance is not leaked or double-counted.\n"

        # Compliance / Security
        "- Compliance: SBV (State Bank of Vietnam) regulations apply to all money movement; TT40 KYC payment limits "
        "(error -1800 KYC limit, -1802 TT40 not satisfied). PCI-DSS scope for card tokenization — card PAN must never be "
        "stored in plaintext. eKYC data (CCCD/CMND/NFC) is PII — must not appear in logs.\n"

        # User Management (UM) — từ Confluence ZTM
        "- User Management (UM) domain: TLSD = 'thanh lý số dư' (balance liquidation via IBFT; requires PIN — biometrics "
        "not accepted — plus face authen on untrusted devices; min amount 2,000 VND). ResetPinV2 = reset payment-PIN "
        "('MKTT') orchestrated by user-pin-public: pending-request check → KBA → risk check → route auto / RBA-MFA / "
        "manual owner flow → OTP → submit may unlink all banks; v2 has whitelist + auto-fallback to v1. "
        "CE Out App = support-ticket handoff from UM flows (TLSD, ResetPinV2, Onboarding, Lock Account, Sim Recycling) "
        "using a one-time AES flow_token (TTL 5 min, single-use in Redis); old app versions get an empty out-app URL and "
        "must gracefully continue the legacy flow. Ticket creation must pre-check pending tickets by request_type to avoid duplicates.\n"
        "- eKYC stack: DR rules block submission with field-level errors (e.g., date conflicts, document side discrepancies), "
        "guarded by a backend bypass count and feature flags; unknown reason codes must degrade to no-op on old client versions. "
        "Multiple vendors are supported for face matching, chip verification, government ID verification (which may have scheduled "
        "maintenance windows), and e-ID app consent callback flows. Face/liveness SDK models have different approval rates. "
        "Services involve onboarding APIs and connectors.\n"
        "- UM incident patterns: Upstream API silently removed a field and strict date parsing broke login — parse upstream/vendor "
        "responses leniently with optional fields and vendor fallback chains. OTP spam abuse via status endpoints and replayed send "
        "OTP tokens — OTP send paths need rate limits, risk check, and fallback authentication challenge. Upstream web server "
        "or routing misconfiguration taking services offline. Backend decision flow enums drive client routing at fund-out — "
        "enum changes need client default-case handling.\n"

        # Common incident patterns
        "- Known incident patterns (real production RCAs):\n"
        "  * Repayment-flow refactor shipped without dedicated testing, riding along with unrelated admin tool deployments → "
        "expired orders triggered debt settlement at upstream bank partners while successful repayments failed to sync → fund loss risks. "
        "Always verify git-diffs between the production state and deploy candidates.\n"
        "  * Settlement files delivered to wrong environment SFTP folders due to manual configuration changes without maker/checker "
        "confirmation. Configuration changes must be peer-reviewed and delivery success monitored.\n"
        "  * Callback payload fields silently dropped across nested data transfer objects (DTOs) and internal gateways; return "
        "codes mapped to null. New API callback fields require end-to-end DTO mapping, contract tests, and sequenced rolling deployment "
        "(library → receiver → api).\n"
        "  * Renaming callback request payload fields broke legacy merchant callback endpoints; dynamically created queue topics "
        "overloaded shared message broker; resource leak in connection handlers exhausted system memory/CPU. Maintain backward "
        "compatibility, static topic policies, and connection resource limits.\n"
        "  * Early return logic on pending status branch in message consumer dropped downstream success notifications.\n"
        "  * Queue message replay/repush during incident recovery risks double payouts or duplicate operations — all replays must be "
        "idempotent and cross-referenced against transaction logs.\n"
        "  * Key-value store configuration restore silently truncated payload values causing lookup failures — data restoration tasks "
        "must undergo integrity validation.\n"
        "  * Duplicate upstream provider callbacks during peak hours led to duplicate operations due to lack of idempotency protection.\n"
        "  * Settlement batch re-run after failure → duplicate journal entries if not idempotent.\n"
        "  * Schema migration on large table without online DDL → table lock incident.\n"

        # Quy trình release / rollout
        "- Release process: mobile follows PQE regression plan — feature MRs into release branch (~1 week), then bug-fix-only day, "
        "final regression, store submit; waiver list needs Squad Lead/PO approval. "
        "Server rollout convention: Internal whitelist → Zion whitelist → All users; canary 1% → 10% → 100% with feature flag. "
        "Impact Analysis rule: if impact spans >3 domains, ZLP Squad Leaders must be notified by email. "
        "MRs are CI-validated against the Why/What/How template (merge-request-auditor).\n"

        # Monitoring / Alert
        "- Monitoring stack: Grafana dashboards for transaction success rate, refund rate, balance drift. "
        "Alerts: PagerDuty for P0 (payment failure rate >1%), Slack/Teams for P1/P2. "
        "Every money-movement release must confirm alert thresholds are set before go-live.\n"

        # ------------------------------------------------------------------
        # QA REWRITE RULES
        # ------------------------------------------------------------------
        "\nRewrite rules:\n"
        "1. Strictly keep the overall risk level, recommendation, project/release details, and finding counts unchanged.\n"
        "2. Rewrite smoke checklists to reference exact function names, table names, endpoints, or error codes "
        "visible in the developer's message or diff — do not use generic placeholder terms.\n"
        "3. If the change touches settlement or reconciliation: always add a specific check for "
        "T+0/T+1 file consistency and settlement mismatch delta.\n"
        "4. If the change touches wallet_balance or ledger_journal: always add a check for "
        "available_balance vs hold_balance consistency and double-entry correctness.\n"
        "5. If the change adds a retry or callback: always flag idempotency check with order_id.\n"
        "6. Preserve the DEV Impact Template Coverage section structure: Overview, Technical Impact, "
        "Risk Product Assessment, Verification & Testing, Rollback & Monitoring.\n"
        "7. Preserve the QE Add-on Assessment section.\n"
        f"8. Output the report in {response_language}. Use Vietnamese only when the developer's raw message is Vietnamese.\n"
        "9. Output ONLY the rewritten markdown report itself. No introductory remarks, no code block wrappers."
    )

    # Inject block kiến thức Confluence (ZTM/PD) liên quan đến nội dung release
    from zp_release_guard.knowledge import render_knowledge_prompt
    system_prompt += render_knowledge_prompt(raw_message, max_blocks=3)

    user_prompt = (
        f"Developer Release Message:\n```\n{raw_message}\n```\n\n"
        f"Draft QA Report:\n```\n{markdown_report}\n```"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    content = llm_client.chat_completion(messages, role="rewrite", temperature=0.2, timeout=90)
    if not content:
        return markdown_report

    # Clean markdown code block wraps
    if content.startswith("```markdown"):
        content = content.removeprefix("```markdown").strip()
    elif content.startswith("```"):
        content = content.removeprefix("```").strip()
    if content.endswith("```"):
        content = content.removesuffix("```").strip()

    if _is_valid_rewrite(markdown_report, content, response_language):
        return clean_latex_symbols(content)
    return clean_latex_symbols(markdown_report)


def _is_valid_rewrite(original_report: str, rewritten_report: str, language: str) -> bool:
    sections = VIETNAMESE_REQUIRED_SECTIONS if _is_vietnamese(language) else REQUIRED_SECTIONS
    if not all(re.search(rf"^## {re.escape(section)}", rewritten_report, re.MULTILINE) for section in sections):
        return False

    protected_markers = []
    for prefix in ("- Overall risk:", "- Recommendation:", "- Finding count:"):
        for line in original_report.splitlines():
            if line.startswith(prefix):
                protected_markers.append(line)

    if _is_vietnamese(language):
        for prefix in ("- Mức rủi ro tổng thể:", "- Khuyến nghị:", "- Số lượng finding:"):
            for line in original_report.splitlines():
                if line.startswith(prefix):
                    protected_markers.append(line)

    return all(marker in rewritten_report for marker in protected_markers)
