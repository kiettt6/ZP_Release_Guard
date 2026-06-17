"""Deterministic knowledge base for the chat agent.

Nguồn: Confluence space ZTM + PD (synced 2026-06-13, đào sâu 2026-06-13). Mỗi
block gắn keyword (đã strip dấu tiếng Việt); select_knowledge() chấm điểm theo
số keyword/mã lỗi khớp và chỉ inject các block liên quan nhất vào system prompt
— giữ prompt gọn nhưng trả lời đúng context. Không gọi mạng, deterministic.

Mỗi block ghi page ID nguồn trong comment để re-sync. Content cố ý dày (bảng mã
lỗi, state machine, ngưỡng) để trợ lý trả lời được câu hỏi cụ thể, có dẫn chứng.
"""

import re

from zp_release_guard.language import normalize_vietnamese_text


KNOWLEDGE_BASE: list[dict] = [
    {
        "id": "kyc_tiers_limits",
        "title": "KYC tiers & wallet/fund-out limit codes",
        "keywords": [
            "han muc", "limit", "k0", "k1", "k2", "k3", "kyc tier", "kyc level",
            "fund out", "fund-out", "fund in", "so du toi da", "100 trieu",
            "vuot han muc", "nang cap tai khoan", "upgrade account", "tier",
            "-135", "-116", "-124", "-148", "-150",
            "-1330", "-1331", "-1332", "-1333", "-1340", "-1341", "-1342", "-1343", "-1600",
        ],
        "content": (
            "KYC tiers & SBV wallet limits (PD 6815898/130086304): K0 (no phone/PIN) = 3 trial txns, 500k VND total. "
            "K1 (phone+PIN) = max balance 1M, fund-out 1M/day, 5M/month. K2 (ID info + linked bank) = 20M. "
            "K3 (full eKYC + linked bank) = max balance 100M, fund-out 50M/day, 100M/month (SBV cap). Refunds are NOT counted against limits.\n"
            "UM fund-out / limit error codes (ZTM 96913997, domain `um`): 1=SUCCESS (proceed). "
            "Business: -135 NOT_ALLOW_FUND_OUT (must upgrade account); -1330/-1331/-1332/-1333 = K0/K1/K2/K3 exceeded DAILY fund-out limit; "
            "-1340/-1341/-1342/-1343 = K0/K1/K2/K3 exceeded MONTHLY limit; -1600 EXCEED_BALANCE (insufficient balance). "
            "System: 0 EXCEPTION, -116 USER_NOT_EXIST, -124 USER_IS_LOCKED, -148 CALL_UM_EXCEPTION, -150 CALL_USER_ASSET_EXCEPTION. "
            "So a '-1342' means a K2 user hit the monthly fund-out ceiling, not a bug."
        ),
    },
    {
        "id": "ekyc_dr_rules",
        "title": "eKYC decision engine (DR rules, AML×Risk×TrueID matrix)",
        "keywords": [
            "dr rule", "dr-0", "ekyc decision", "trung chan dung", "duplicate face",
            "auto reject", "manual review", "postpone reject", "trueid", "aml", "liveness",
            "ocr", "selfie", "giay to het han", "khong trung danh tinh", "dinh danh",
            "blacklist", "instant reject", "risk engine", "decision matrix", "bypass",
            "dr-031", "dr-036", "dr-037", "dr-045", "dr-049", "dr-064", "dr-065",
        ],
        "content": (
            "eKYC final decision (PD 91003033) = matrix of AML × Risk × TrueID(KYC) verdicts. AML Instant Reject always wins; "
            "any Manual anywhere → Manual Review. v2 adds Postpone Reject = shown to user as PROCESSING, auto-rejected by a job after 24h "
            "(scan every 30 min, so effective 24h+0-30m). v2 also escalates two combos to Instant Reject that v1 left Manual "
            "(AML Approve+Risk Manual+KYC Instant Reject; AML Manual+Risk Manual+KYC Instant Reject). "
            "Timeouts: Risk no-response → treat as Manual; AML no-response → treat as auto-approve. Only whitelisted users actually call Risk/AML. "
            "Undefined TrueID DR → ENGINE_DR_DEFAULT ('Vi phạm điều kiện định danh').\n"
            "DR codes (DR-001..065): DR-017 photo-of-photo ('Chụp qua thiết bị khác', manual after 3 auto-rejects), DR-023 face-on-ID≠selfie (bypass 3x), "
            "DR-027 ID already registered, DR-029 expired doc, DR-031 illegal issue/birth/expiry date combo, DR-036/037 duplicate face in DB ('Trùng chân dung'), "
            "DR-045 user input ≠ OCR, DR-049 OCR-front ≠ MRZ-back on chip CCCD (=IL-012), DR-050 OCR hits AML, DR-059..065 NFC/VNeID vs OCR mismatches "
            "(DR-064=ReasonCode 110, DR-065=ReasonCode 111, both bypass 3x). check_result: 0=not run,1=pass,2=fail,3=uncertain.\n"
            "Whitelist single-DR INSTANT REJECT: DR-043/031/045/028/009/029/025/030/041/035 + SYSTEM_VERIFY_IMAGE_FAIL_LIMIT_TIME. "
            "Multiple-DR instant-reject combos: DR-036+DR-037+any; DR-045+DR-036/037; DR-036/037+DR-017; DR-012+DR-036/037; DR-013+DR-012.\n"
            "Duplicate-face (DR-036/037) algorithm vs TrueID top-7: same Name+DOB+id_type+id_number → auto approve; same Name+DOB+id_type but DIFFERENT id_number → instant reject; "
            "same Name+DOB but different id_type → auto approve; else manual. (Names normalized: strip tones, uppercase.)\n"
            "Re-eKYC identity change (blocks submit, priority 2): 1-2 fields changed → manual ('Không trùng danh tính'); 3-4 changed → block ('...tài khoản đã từng sử dụng danh tính khác'). "
            "eKYC same day as account creation → manual. Instant-reject 2× within 3 days → CS manual (INSTANT_REJECT_2_TIMES).\n"
            "Bank-match (priority 1): name match but id mismatch on a linked bank → block ('...tài khoản đang liên kết với ngân hàng của người khác'); name-only mismatch → manual (DR_NOT_MATCH_BANK_NAME). id_type 3=5(=6 for NFC).\n"
            "NFC face-score thresholds: >70 = match (pass), <60 = fail (auto reject), 60-70 = manual review.\n"
            "Risk info-code ranges: 502xxx fake/clone account, 503xxx returning bad actors, 504xxx high eKYC velocity, 505xxx edited-selfie/fake-eKYC model, 509xxx other suspicious. "
            "Specific Risk reject codes: 20002 device blacklist, 20007 device exceeded #accounts KYCed, 20025 fake-KYC blacklist, 20026 face blacklist. "
            "AML scoring (bits Country=1,ID=2,Name=4,DOB=8,Face=16): Country bit set → always Instant Reject (sanctioned country); score thresholds Rejected≥17, Manual 7-16, Passed <7."
        ),
    },
    {
        "id": "ekyc_nfc_reason_codes",
        "title": "user-ekyc-nfc reason codes, statuses, vendor fallback, face authen",
        "keywords": [
            "reason code", "reasoncode", "nfc status", "user-ekyc-nfc", "user_ekyc_nfc",
            "bca", "bca maintenance", "jth", "vendor fallback", "face authen", "face authentication",
            "s0", "s5", "s7", "strategy code", "liveness", "nfc scan", "c06", "migrate",
            "event tracking", "funnel", "zpa", "zmp", "trueid timeout",
        ],
        "content": (
            "user-ekyc-nfc proto (ZTM 189383083). NFC user status: 1 NO_NFC, 2 NFC_NO_BCA, 3 COMPLETE_NFC, 4 PROCESSING. "
            "Ticket status: 1 PROCESSING, 2 AUTO_APPROVE, 3 AUTO_REJECT, 4 MANUAL_APPROVE, 5 MANUAL_REJECT, 6 AUTO_APPROVE_BCA, 7 MANUAL_APPROVE_BCA, 8 WAIT_EKYC, 9 EMBED_EKYC.\n"
            "Key ReasonCodes: 10/11/12 MISMATCH_ID_NUMBER/NAME/DOB, 13 MISMATCH_FACE_AUTHEN (reject), 21 ...MANUAL, 22 BCA_MAINTENANCE, 30 TRUEID_ERROR, 31 JTH_ERROR, "
            "34 UNSUPPORTED_APP_VERSION, 36 USER_LOCKED, 41 MISMATCH_FACE_AUTHEN_TIMEOUT_MANUAL (TrueID timeout), 42 ...NOT_FOUND_MANUAL (not in TrueID index), "
            "53 FAIL_ISSUE_DATE_BEFORE_KYC, 98 TEMPORARY_BCA_MAINTENANCE, 110 DR_064, 111 DR_065, 114 FAILED_DB_V2_CONVERT, 119 FAILED_MIGRATION_LOCK, 125 REPOSITORY_V2_ERROR. "
            "(22 vs 98: 22 = BCA under maintenance, 98 = temporary BCA maintenance.)\n"
            "Vendor fallback: verify_source ∈ {jth, trueid, vneid}; verify_source_fallback ∈ {jth, trueid, trueid_jth, jth_trueid, vneid}; face_authen_vendor ∈ {trueid, zlp} with fallback {trueid, zlp, zlp_trueid}. NFCDataType 1=NFC(scan), 2=VNEID.\n"
            "Face authen (ZTM 194740700): Ticket status 1 APPROVE, 2 REJECT. strategy_code S0=1, S5=5, S7=7. S0 = legacy ZaloPay liveness SDK (hangs on new devices, replaced from app v10.2.0); S7 = TrueID SDK liveness. "
            "Face-authen rate limits: 15-min and 24h windows. Score range [0,1] with L/U thresholds.\n"
            "Event funnel (PD 230268931): prefix 01=ZPA (native app), 02=ZMP (Zalopay-in-Zalo); screens 144x=NFC, 149x=eKYC. Funnel: 0x.1490.999 start → 1492.003/005 ID capture/validate → 1443.000 NFC scan → 1493 OCR submit → 1496 selfie SDK → 1498.999 end (result: auto_approve/auto_reject/processing/cancel). "
            "flow enum: 1=eKYC, 2=adjust, 12/13=NFC, 17/18=eKYC link NFC, 19=eKYC by VNeID. id-type: cmnd=1, passport=2, cccd=3, cccd chip=5, can cuoc=6."
        ),
    },
    {
        "id": "tt40_compliance",
        "title": "TT40 (Circular 40) compliance, force NFC, topup mode D",
        "keywords": [
            "tt40", "thong tu 40", "toro", "force nfc", "nfc bat buoc", "c06", "bca",
            "vneid", "chuyen tien", "money transfer", "qrnt", "qr nhan tien",
            "top up mode d", "topup mode d", "10 trieu", "10m", "circular 40", "compliance",
        ],
        "content": (
            "TT40 (SBV Circular 40, PD 219694744): to pay with WALLET balance (pmcid 38) the user needs 'Toro Full' = age ≥16, valid chip-CCCD eKYC, "
            "NFC biometric verified with C06 (tap card or VNeID sync), occupation + permanent address, matching bank link. 'Toro 0.5' = valid chip eKYC only. SOF=bank (pmcid 37/39) needs only valid chip eKYC.\n"
            "Money Transfer force-NFC (PD 333542730, June 2026): new K0/K1 users blocked at transfer; existing non-NFC users forced when monthly accumulated + requested transfer-out ≥ 10M VND "
            "(ALL SOFs, calendar month — e.g. 9M accumulated + 1.5M txn → blocked, +999k → allowed); AML-blacklist users forced on next transfer. "
            "Old K2-mapbank '1 txn max 1M' trial rule REMOVED ~10/06/2026. NAPAS receive & existing-QR receive cannot be blocked (accepted risk, mitigated by notification). "
            "QRNT (QR nhận tiền) creation requires eKYC+NFC for new users. MMF deposit loopholes (VietQR first-deposit, cashback-to-MMF, stock-withdraw-to-MMF) being closed; withdraw 100M forces NFC. TLSD reduced from 3 to 1 time. "
            "If C06 verify fails during NFC, user proceeds; a background cronjob re-verifies.\n"
            "Topup mode D codes returned to banks (PD 230275110): 10 = account not eligible (bank must revert the money), 11 = top-up limit exceeded."
        ),
    },
    {
        "id": "transfer_topup_errors",
        "title": "Transfer/Topup/Withdraw error codes & order states",
        "keywords": [
            "error code", "ma loi", "transfer", "chuyen tien", "topup", "nap tien",
            "withdraw", "rut tien", "fundback", "hoan tien tu dong", "orderstatus", "order status",
            "ibft", "pending", "deliver", "next action", "transfer_core",
            "-8003", "-8001", "-8002", "-8005", "-8009", "-8010", "-8129", "-8131", "-8136",
            "-8142", "-8144", "-8350", "-8351", "-8359", "-8500", "-9998", "-332", "-3008",
            "-3004", "-1000", "-1004", "-267", "-268",
        ],
        "content": (
            "Sign convention (ZTM 165231347/102206530): orderStatus >1 = still PROCESSING, =1 SUCCESSFUL (final), <1 = error/failed. "
            "So 6 PAYMENT_SUCCESS (paid at TPE) is NOT final; only 1 is.\n"
            "Delivery band (−8001..−8010): -8001 DELIVER_PENDING, -8002 DELIVER_EXCEPTION, -8005 DELIVER_MANUAL_CHECK = PENDING (fate unknown, do NOT tell user it failed); "
            "-8003 DELIVER_FAIL_AUTO_REFUND, -8009 DELIVER_FAIL_REFUNDED, -8010 DELIVER_FAIL_WAITING_REFUND = FAILED with money refunded (FUNDBACK). "
            "Process band: -8350 no TPE callback after 30 min (system queries TPE), -8351 TPE debit failed, -8359 exceeded next-action (e.g. OTP attempts), -8361/-8362/-8363 = PENDING. "
            "Check band: -8129 withdraw bank not configured (needs BankInfo+BankConfig), -8131 over credit limit, -8136 under min, -8142 user blacklisted, -8144 over KYC amount limit, "
            "-8132/-8133 bank inactive/maintenance. Control: -8500 FORCE_APP_UPDATE, -8501 USER_REACHED_LIMITATION, -9998 SERVICE_MAINTAIN. Auth: -73 token invalid, -105 logged out. "
            "API-domain band: -8202/-8203 TPE, -8204/-8205 UM, -8214 Bank Connector, -8217 Promotion, -8220 Risk.\n"
            "transfer_core (ZTM 96913997): states 1 R_SUCCESSFUL (final), 2 ORDER_CREATED, 3 PAYMENT_ACCEPTED, 4 VALIDATED, 5/6 trans submitted to PE. "
            "System: -1000 DB, -1001 Redis, -1002 Kafka, -1004 RPC. Business: -332 blocked by Risk (KYC challenge — a business rejection, not a bug), -3003 order not found, -3004 order expired, -3008 duplicated payment. "
            "transfer_permission: -1 amount over upper limit, -2 under lower limit, -3 SoF maintenance, -4 SoF inactive.\n"
            "trans_status in logs (ZTM 127918540): -267 = failure at BANK step, -268 = failure at PROMOTION step; the real code is in step_result.\n"
            "SBV rule (ZTM 122391248): a transfer with SoF=BANK is ALWAYS 2 transactions — (1) topup Bank→sender wallet, (2) wallet→wallet transfer. A failure can be isolated to either leg; reconcile both."
        ),
    },
    {
        "id": "card_processing",
        "title": "Tap2Pay/Visa/Pismo processing codes, MTI, idempotency, reversal",
        "keywords": [
            "tap2pay", "visa", "pismo", "mti", "processing code", "0100", "0120", "0200", "0220",
            "0400", "0420", "advice", "authorize", "capture", "clearing", "reversal", "refund card",
            "f95", "f61", "bctransid", "rrn", "stan", "idempotency", "exactly once", "issuer",
        ],
        "content": (
            "Pismo/Visa processing codes (ZTM 278863112): 00 Purchase (Debit), 01 Cash Withdrawal (D), 02 Adjustment-Debit/undercharge (D), 10 Account Funding/AFT (D), 11 Quasi-cash (D), "
            "20 Credit Voucher/refund (Credit), 22 Adjustment-Credit/overcharge (C), 26 Original Credit/payout-to-card (C), 30 Balance Inquiry (Zero). "
            "(Authoritative: pc 02 = undercharge/Debit, pc 22 = overcharge/Credit — do not trust the swapped table on page 325195695.)\n"
            "MTI: 0100 authorize (DMS, hold), 0120 authorize advice, 0200 financial/clear immediately (SMS), 0220 payment advice, 0400 reversal/refund, 0420 refund advice, 0422 reversal advice. "
            "Any (MTI, processing_code) pair NOT in the mapping must be REJECTED, not processed.\n"
            "Idempotency (ZTM 335579107): MTI 0x00 (0100/0200/0400) must execute EXACTLY ONCE per Visa request — replay returns the stored result. "
            "MTI 0x20 advices retry when (network decision=approved) AND status∈{Failed,Pending,Processing}; BC retries on the SAME bcTransID; PBW retries only when PE status is explicitly Failed (pending/processing → return error, wait). "
            "Each payment/refund may be adjusted by AT MOST ONE advice (0220). Lookback for original transaction = 12 months.\n"
            "Unique keys: Authorize (01XX) = MTI+Processing_Code+F11_stan+F62.2_transaction_identifier+F63.3_message_reason_code; Reversal (04XX) adds F37_RRN+F95_replacement_amounts. "
            "Hop keys: Pismo→BC = field set; BC→PBW = bc_trans_id; PBW→Core = app_trans_id+app_id+payment_request_id. Duplicate app_trans_id → error -68.\n"
            "Refund (0200/0220, pc=20) is NEVER refunded online — BC returns approve to Pismo, actual refund executes at T+n reconciliation. Partial reversal NOT supported by Payment Core phase 1.\n"
            "Reversal amount: always reconcile via F95.1 (positions 1-12), never F4/F6 directly. If F95.1 empty → 0 (full reversal); if F61.3 empty → F61.3 = F95.1 × (F6/F4). PBW reverses (current held amount − F61.3)."
        ),
    },
    {
        "id": "settlement_reconciliation",
        "title": "Settlement & reconciliation (Tap2Pay 4 segments, mismatch matrix, BSS)",
        "keywords": [
            "settlement", "doi soat", "reconciliation", "recon", "payout", "sao ke",
            "clearing", "settlement file", "sftp", "merchant settlement", "resubmit",
            "fund loss", "mismatch", "bundle", "bss", "batch", "vcb", "ctg", "vietinbank",
        ],
        "content": (
            "Tap2Pay reconciliation (ZTM 335579808) — 4 segments: (1) Transaction Recon (Visa×BC, owner OP, T+2), (2) Fund Recon (BC×TPE, FA, T+2 — KNOWN GAP: excludes refunds), "
            "(3) Bank Statement Recon (Visa×BC×STB/Sacombank, FA, T+2), (4) Bundle Recon (TPE order lifecycle, FA, E+2 where E=A+5/10/20/30, POS default A+5). "
            "FA may complete/clear an order only after Bank Statement Recon is done through end of day T. Statuses S/F/P/NA.\n"
            "Mismatch matrix (ZTM 335579808/322294222): debit-type (Authorize/Capture/Adjust-Undercharge/Reversal-Refund) at BC=S,Visa=F → set BC failed + create refund ticket; BC=F/P/NA,Visa=S → resubmit. "
            "Credit-type (Reversal→Cancel/Void, Adjust-Overcharge, Refund) at BC=S,Visa=F → FUND LOSS, report to tech; BC=P,Visa=F → if TPE=S fund loss, if TPE=F set BC failed. "
            "A refund matched to a reversal (TID+authorizationCode+pan_token) must NEVER be resubmitted (fund-loss prevention).\n"
            "Resubmit MTI (ZTM 322294222) always uses the advice form: 01x0→0120, 02x0→0220, 04x0→0420. Net 0x00 vs 0x20 by TID/RRN/STAN/amount/currency/transmission_time, order DESC, take first row.\n"
            "Merchant settlement BSS (ZTM 333543650): orchestrates MCPF↔per-bank connectors; VCB batch 3000 (Kafka), CTG batch 100 (/invoke_bank API). subtranstype 2601 submit, 1501 query, 1801 beneficiary-name. "
            "settlement_request PK merchant_request_id = idempotency key (one statement = one bank). State machines: statement INIT→PROCESSING→COMPLETED|REJECTED; batch INIT→VALIDATED→PROCESSING|PENDING→COMPLETED; record final = VALIDATE_FAILED|SUCCESS|FAILED|PENDING. "
            "webhook_event has UNIQUE event_id (dedup). StuckBatchSweep re-drives stuck batches via polling (poll_attempt).\n"
            "Settlement file/delivery-config changes need maker-checker + merchant confirmation + delivery monitoring."
        ),
    },
    {
        "id": "agreement_pay_partners",
        "title": "Agreement Pay / autopay error codes, partners, monitoring",
        "keywords": [
            "agreement pay", "autopay", "auto-debit", "binding", "tiktok", "grab", "lazada",
            "apple", "google", "pay token", "paybytoken", "lien ket vi", "bhx", "xanh sm",
            "-1002", "-1007", "-1010", "-1013", "-1800", "-1802", "-68", "-1019",
            "-7240", "-7241", "-63", "querybalance", "submitpay", "monitoring", "success rate",
        ],
        "content": (
            "Agreement Pay = OAuth2 tokenized merchant payment (binding → pay_token → PayByToken/CheckBalance). Core service aqr-agreement-agreement-pay. Source ZTM 316896184.\n"
            "Core 2.1 codes: -1801 system maintenance, -401 illegal request, -402 unknown app / wrong signature, -101 token/order/user not exist, -1002 agreement invalid (link cancelled), "
            "-1007 agreement expired, -1009 account locked, -1010 insufficient funds, -1013 payment limit, -1800 over KYC limit, -1802 not TT40-compliant, -68 duplicate app_trans_id, -1019 wallet exceeded binding count. "
            "(Binding/query-balance path never returns -68/-1010; those are Submit-pay only.)\n"
            "Apple (Charge/Reversal, string codes): APPROVED, DECLINED_INSUFFICIENT_FUNDS, DECLINED_NONKYC_AMOUNT_LIMIT_EXCEEDED (KYC limit OR not TT40), DECLINED_SUSPECTED_FRAUD, "
            "ERROR_ALREADY_REVERSED, DECLINED_TIME_EXCEEDED, ERROR_DOWNSTREAM_TIMEOUT ('being processed').\n"
            "Google (Capture/Refund, VND-only): non-VND → ACCOUNT_DOES_NOT_SUPPORT_CURRENCY. NO_GOOD_FUNDING_SOURCE_AVAILABLE = KYC<2 / unmappable TPE fail / TT40 ineligible. "
            "TPE→Google maps: INSUFFICIENT_FUNDS=TPE -49/-62/-63/-217, ACCOUNT_CLOSED=TPE -61/-66, RISK_DECLINED=TPE -333/-332/-357/-348/-352/-354/-356, CHARGE_EXCEEDS_DAILY_LIMIT=TPE -365. REFUND_WINDOW_EXCEEDED = query refund returnCode -13.\n"
            "Lazada -7xxx (paybytoken/paybytokenusingotp/querybalances): -63 insufficient (pay path), -7240 insufficient (querybalances only), -7000 not TT40, -7202 zptoken invalid, -7236 invalid amount, "
            "-7241 failed to authorize (KYC/limit/risk), OTP: -7031 invalid, -7033 expired, -7034 wrong, -7035 retries exhausted. Lazada is the partner with OTP-in-pay.\n"
            "Per-partner: Grab/BHX/XanhSM use the Authorize family (authorize/capture/cancel pre-auth; Grab 'Pay & Refund' = auth is a real payment, cancel=refund, expired auths auto-refunded by cron). "
            "Apple = Charge+Reversal only. Google = VND-only. TikTok (Shop 1413, Live 1411, Promote 1593, disbursement 1919) uses Core 2.1 SubmitPay+QueryBalance — SR drops are often network/peer-side (2024 firewall SYN-flood block of TikTok IPs; TikTok may self-disable ZaloPay).\n"
            "TikTok monitoring (ZTM 200819240, dashboard m2kS2HdIk): Shop 1413 E2E SR warn ≤70 / crit ≤65 @1m, SubmitPay SR ≤80/≤70, P99 latency ≥5s @5m; Live 1411 E2E ≤50/<40 @5m; Promote 1593 E2E ≤55/<45 @5m. Grab/Lazada/Apple have no per-app threshold table on this page."
        ),
    },
    {
        "id": "retry_idempotency_semantics",
        "title": "Retry / idempotency / replay semantics (company-wide)",
        "keywords": [
            "retry", "idempotency", "idempotent", "resubmit", "replay", "duplicate",
            "double debit", "double payout", "chong trung", "goi lai", "operation status",
            "side effect", "response replay", "operation_id",
        ],
        "content": (
            "EA glossary (ZTM 297827743): RETRY = same payload + same Idempotency-Key + same operation_id, allowed ONLY while operation status = PROCESSING (timeout/5xx), never for validation/policy errors. "
            "RESUBMIT = corrected input → NEW key + NEW operation_id. RESPONSE REPLAY = return persisted result without re-execution (business_status, error_code, ids, amount must be identical; request_id/trace_id may differ). "
            "Operation status: PROCESSING / COMPLETED / REJECTED (terminal = no retry). Business status (PENDING/SUCCESS/FAILED) is NOT a retry signal.\n"
            "Order FAILED does NOT mean retry-safe — dangerous side effects (SoF debit, ledger entry, settlement, merchant IPN/webhook, side-effecting Kafka events) may already have occurred; track the side-effect boundary. "
            "Controls: idempotency key (execution level) + unique insert (entity level) + idempotent downstream (ledger by txn_id, consumers dedupe by event_id).\n"
            "Visa/Tap2Pay (ZTM 335579107): MTI 0x00 exactly-once; advices 0x20 retry on same bcTransID; at most one advice per payment; unmapped MTI/processing-code → reject."
        ),
    },
    {
        "id": "bank_maintenance_monitoring",
        "title": "Bank Connector alerting, maintenance, new-bank config, VietQR",
        "keywords": [
            "maintenance", "bao tri", "alert", "monitor", "canh bao", "bank connector",
            "-5000", "-5002", "-5015", "success rate", "napas", "vietqr", "upi", "new bank",
            "tich hop ngan hang", "telco", "nap dien thoai", "bankfunction", "emvco",
        ],
        "content": (
            "Bank Connector alerting (ZTM 59715846): HIGH CRITICAL at 1 txn/5m for -5000 (ZaloPay guarantee account OUT OF BALANCE — act immediately) and -5005; "
            "bank-side -9201 call-fail/-9202 timeout at 3/5m (5/5m for NAPAS3, IBFT, Visa Direct transType 1801/2501/2601; VietQR transType 2700 at 5/5m). "
            "Bank-side -5002/-5015/-5001/-5014 at 5/5m (9/5m IBFT): wait 30'-1h, then enable maintenance if the bank doesn't stabilize. "
            "Success-rate alerts: hourly SR drop >25% vs same-hour-7-day avg (min 5 txn), hourly SR <10%, or error ratio doubling (>20 errors/h).\n"
            "Maintenance (BAM, ZTM 87208011): objects = Bank (BankCode), Bank Function (AppVersion-BankCode-Platform-BankFunction), BIN; types Manual / Schedule / Daily / Automatic (system detects degradation, operator approves).\n"
            "New bank (ZTM 130086008): configure bankFunction on CDN tool — 301 link-by-card, 302 link-by-account (mode A), 104 pay-by-account-token, 105 pay-by-card-token, 501/502 withdraw, 601/602 deposit. Withdraw also needs BankInfo + BankConfig (cps-withdraw), else error -8129.\n"
            "Telco topup (ZTM 59936197): enable provider maintenance when the topup-v2 dashboard shows >20% pending for that provider; maintenance triggers an auto email notice.\n"
            "VietQR/UPI EMVCo (ZTM 153769759): payment -77 EMVCo_PAYMENT_CONFIRM_PAY_UNKNOWN_ERROR = Pending (the only non-fail/non-success), 1 = success; UpdateTransStatus 1=success, 5=failed, 68=pending; UPI -2013 QR not found."
        ),
    },
    {
        "id": "bank_connector",
        "title": "Bank Connector (BC): architecture, return codes, callbacks, deploy order",
        "keywords": [
            "bank connector", "bc-api", "bc-bank-receiver", "bankqrreceiver", "bc-logger",
            "connector", "ibft", "vietqr", "upi", "cashin", "cashout", "disbursement",
            "escrow account", "guarantee account", "tai khoan dam bao", "returncode", "return code",
            "callback", "ipn", "rba", "idempotency", "dedup", "deploy order", "shared-lib",
            "subtranstype", "updatetransstatus", "reconciliation key", "sf2transactionidentifier",
            "-5000", "-5800", "-5007", "-9205", "-9201", "-9202", "-9203", "-9204", "-9208",
            "-3020", "-3021", "-3024", "-8129",
        ],
        "content": (
            "Bank Connector architecture (ZTM 329193910/181515495): bc-api (core orchestrator, routes by bankConnectorCode) → per-bank connectors (bc-bank-mb2/vpb2/vccb/msb2, shared bc-bank-oao). "
            "Inbound bank callbacks arrive at bc-bank-receiver / bankqrreceiver → forward to bc-api via /zpbankgateway/bank/invoke. bc-logger persists idempotency + logs to Kafka. "
            "Sync (legacy) flow has a proxy hop → -9205 INTERNAL_BC_TIME_OUT and a slow bank stalls the shared queue, hitting healthy banks; async V3.1 (queue between bc-api and connectors + per-bank rate limit + 'transaction expired') eliminates -9205 and isolates slow banks.\n"
            "Return-code catalog (ZTM 59715794). ZaloPay-side -9xxx: -9000 SYSTEM_ERROR, -9001/-9003 data conversion, -9100..-9106 DB/cache (→-9000), -9203 CALL_UM_EXCEPTION (Fail), -9204 CALL_TPE (Pending), -9205 INTERNAL_BC_TIME_OUT (Pending), -9206 CALL_MP, -9208 CALL_OFP (VietQR/UPI). Bank-side: -9201 CALL_BANK_EXCEPTION, -9202 CALL_BANK_TIME_OUT. "
            "-5xxx: -5000 BANK_ZION_ESCROW_ACCOUNT_BALANCE_EXCEEDED (escrow/guarantee account out of balance — FAILS all txns through that connector, High-Critical alert at 1 txn/5m), -5800 escrow LOCKED, -5001 not connected, -5002 unknown error, -5003 bank maintenance, -5005 ZaloPay maintenance, -5007 BANK_SYSTEM_ERROR, -5014 exception, -5015 timeout, -5070 trans not found, -5209 invalid signature, -5429 invalid message format, -5400..-5429 QR family. "
            "Dedup/idempotency codes: -3020 DUPLICATED_BANKTRANSID, -3021 DUPLICATED_ZPTRANSID, -3024 DUPLICATED_TRANSACTION, -5043/-5057 duplicate transID/traceNo. Missing-callback: -3155 BANK_NO_RECEIVE_IPN_CALLBACK (Pending). Config: -8129 CHECK_BANK_CONFIG_NOTEXIST.\n"
            "subTransTypes: 1102 register/link bank account (OAO), 1801 IBFT inquiry, 2601 transfer-to-card, 2611 transfer-to-account, 2700 VietQR payment inbound, 2702 VA create, 3141 manual refund. VietQR pay-fail auto-reverts via IBFT 2611.\n"
            "Callbacks are deduped via bankIdempotencyLog (bank-initiated) / bcIdempotencyLog (BC-initiated); during the VietQR DB split, idempotency is written to BOTH old+new DB. Inbound bank callbacks MUST be idempotent (double IPN = double credit / fund loss).\n"
            "Upstream callback silent-drop bug: A callback status field is dropped across shared-lib DTO → receiver → API, so return code is always NULL. Fix = add field to shared-lib DTO, forward in receiver, map in API convertTransEntity(); MANDATORY deploy order shared-lib → receiver → API (verify on staging at each step).\n"
            "New bank (ZTM 130086008): bankFunction codes 301 link-by-card, 302 link-by-account, 104 pay-by-account-token, 105 pay-by-card-token, 501/502 withdraw, 601/602 deposit; withdraw also needs BankInfo + BankConfig else -8129. "
            "Reconciliation key for Tap2Pay/Visa resubmit = sf2TransactionIdentifier (DE62.2); business_line strictly 'tap2pay'; DE95 parsed from first 12 chars. "
            "Failover: on bank instability switch disbursement to an error scenario and move incoming QR routing to an alternate bank. Maintenance auto-enables via BAM (Bank/BankFunction/BIN objects)."
        ),
    },
    {
        "id": "um_account_flows",
        "title": "UM flows: ResetPinV2, TLSD, CE out-app, OTP, auth-challenge, VNeID",
        "keywords": [
            "reset pin", "resetpinv2", "change pin", "mktt", "mat khau thanh toan",
            "tlsd", "thanh ly so du", "liquidate", "ce ticket", "out-app", "flow_token",
            "otp", "smart otp", "kba", "mfa", "rba", "lock account", "khoa tai khoan",
            "dang nhap", "login", "session", "auth challenge", "vneid", "owner", "consent",
            "request_type", "trusted device",
        ],
        "content": (
            "ResetPinV2 (ZTM 112092541): orchestrated by user-pin-public. Gate chain: pending-request check (user-owner-framework) → KBA status/block (user-kba) → risk check → route to "
            "auto / RBA-MFA (multi_factor_authen + authen-challenge, action code 10000) / manual owner flow → OTP (user-otp) → submit may UNLINK ALL banks (bank_mapping) → user-life-cycle-v2 updates PIN. "
            "Falls back to V1 at two gates: is_v2==false (whitelist-v2 / eKYC-BCA check) and limit-v2 reached. RESET_PIN request_type = 9.\n"
            "TLSD / thanh lý số dư (ZTM 236984078, 297815275): IBFT cash-out of remaining balance. Preconditions: balance > 0; min amount 2,000 VND (below 2k after loading → pending). "
            "Auth = PIN (biometrics NOT accepted) + face authen if device not trusted; now limited to 1 time (was 3). Logic: if temp balance==0 OR wallet==0 → SINGLE txn (LQ001 main / LQ002 temp) else DUAL parallel. "
            "ReasonCodes: BALANCE_NOT_MATCH 23, EXCEED_LIMIT_AMOUNT, RATE_LIMIT 30, MIN_BALANCE 31, LIQUIDATE_DISABLED 33.\n"
            "CE Out-App (ZTM 329215406, 333514548): hands UM flows (TLSD, ResetPinV2, Onboarding, Lock/Close, Sim Recycling) to an out-app support web via flow_token = AES({user_id, request_type, expire_time}), TTL 5 min, one-time-use in Redis, secure channel (not URL). "
            "Unsupported app_version/platform → empty internal_out_app_url → client continues the legacy flow. request_type: PHONE_RECYCLING 2, LIQUIDATE_BALANCE 6, CLOSE_ACCOUNT 7, RESET_PIN 9 (request_source='UM'). "
            "Pending-group ticket statuses that BLOCK a duplicate submit (show tray): PENDING 3, PENDING_FOR_WAITING_CUSTOMER 7, PENDING_FOR_RISK 9, PENDING_FOR_LEAD 10; others (NONE 0, CREATED 1, WAITING 2, REJECTED 4, APPROVED 5, EXPIRED 6, CLOSED 8) do not. "
            "searchTicket is called only when the user taps 'Gửi yêu cầu hỗ trợ', never on entry. Owner-protection screen (TLSD/ResetPinV2 retry-limit hit): 'Tài khoản của bạn đang được Zalopay bảo vệ', response in 48h.\n"
            "Auth-challenge (PD 189379150): auth types pin 1, bio 2, OTP 3, face 4 (default retry 3), ekyc 5, adjust-ekyc 6, nfc 7, ekyc+nfc 8, smart otp 10, SMS-OTP/OTP_V2 12, OTP_OR_SMART_OTP 13. Source IDs: cashier 2, installment 3, liquidate balance 11, owner verification 25, payment authen 26.\n"
            "OTP spam (ZTM 59708146): attack via /v2/account/phone/status → send_otp_token → spam /v2/account/otp; controls = per-phone + per-IP rate limit, Risk Engine checkpoint before send, CAPTCHA when Risk flags spam. OTP TTL 5 min. Smart OTP (ZTM 200808277): 2-step register (validate pin/pin_session, then validate OTP requestid); secret_key+algorithm+expiry stored in device secure store; transactions mix transid into the key.\n"
            "VNeID (ZTM 237009293): app → user-vneid → vneid-connector (RAR layer, rar-um.zalopay.vn) → national VNeID. Consent: init creates nonce → face image SDK-signed/encrypted → /agent/init with CCCD → user accepts/rejects in VNeID app → callback consent result → /api/get-transaction → app polls ~30s. ZaloPay must expose a revoke-consent callback."
        ),
    },
    {
        "id": "promotion_cashback_voucher",
        "title": "Promotion / cashback / voucher / NBA",
        "keywords": [
            "voucher", "cashback", "promotion", "khuyen mai", "hoan tien", "ma giam gia",
            "revert", "reward", "campaign", "nba", "phat bu", "stamp", "fact_id", "trigger_point",
            "-7044", "-7030", "-7053", "-7010", "transtype 11", "conditionresults", "tu006",
        ],
        "content": (
            "Voucher states (PD 67711580): Create (Chưa phát) → Given (Đã phát/active) → Verified (Đã xác thực) → Used. "
            "REVERT = voucher held (treo) after a FAILED cashier apply; the system auto-flips Revert→Given after 30 MINUTES, then it's usable again — the #1 answer for 'voucher disappeared'. Expired is derived (expiry < now).\n"
            "Cashback payout signature (PD 84407239): TPE Transtype=11, AppID=1, PmcID=38, addressed to the recipient. Campaign = first 14 chars of campaignCode. EXCLUDE Referral and 'phát bù' (compensation) when counting cashback. "
            "TransID = the purchase that earned cashback; refTransID = the cashback credit itself. If productCode==TU006, re-look-up by refTransID. No fixed cashback when the transaction already used a voucher (PD 125672285).\n"
            "Promotion present-service errors (ZTM 57785778): -7001 fail, -7010 duplicate request, -7030 reward pool exhausted, -7044 source wallet out of money, -7045 TPE deadline exceeded, -7050..-7053 voucher delivery (-7053 out of voucher), -7060 stamp. "
            "Reward types: CASHBACK_FIX/PERCENT, VOUCHER_FIX, STAMP, COMBO_MASTER. Re-process job idempotency: calls getTransStatusFromAppTransId — if trans already exists, SKIP resubmit (no double cashback); pending -59 → BookKeeping CHARGE query, -16/-17 → ADD_CASH query.\n"
            "NBA triage (PD 285002839): NBA = Next Best Action rule engine. trigger_point_id 128 (with transID) or 128/249 (without); 249 = OAO bank-account-opening, 43 = Flash Sale. "
            "fact_id 889 = risk check (1=no risk, 0=suspected, -1=risk; pass usually needs ∈{0,1}); fact_id 1691 = counter/budget check (pass = ==1); fact_id 6855 = referral. "
            "In flow_results, a node with conditionResults false is where the user got stuck — the LAST false node explains why no reward; reward node = type ACTION, action_type PRESENT.\n"
            "IBFT fee voucher (PD 45172624): refunds the transfer fee (100%, max 10,000đ) AFTER a successful transaction — NOT an upfront discount; limit 1/task/month (Baemin-Lazada 2), max 7/user/month, 7-day validity."
        ),
    },
    {
        "id": "ekyc_event_tracking",
        "title": "eKYC event tracking & funnels (analytics)",
        # PD 230268931
        "keywords": [
            "event tracking", "event id", "funnel", "tracking", "event list",
            "dashboard ekyc", "1490", "1498", "1443", "analytics", "screen code",
        ],
        "content": (
            "eKYC event tracking (PD 230268931): event ID format 0x.SSSS.NNN; section 01=ZPA (native app), 02=ZMP (Zalopay-in-Zalo); screen ranges 144x=NFC, 149x=eKYC. "
            "Funnel anchors: 0x.1490.999 start flow → 1491 guide → 1492.003/005 ID camera/capture/validation → 1443.000 NFC scan → 1493.000/011 OCR screen/submit-fail → 1496.000 selfie SDK → 1498.000/999 result page/end (result: auto_approve/auto_reject/processing/cancel) → 1499 NBA banner. "
            "flow enum: 1=eKYC, 2=adjust, 5/15=eKYC merge NFC, 12=NFC, 17/18=eKYC link NFC, 19=eKYC by VNeID. ID-type codes: cmnd=1, passport=2, cccd thường=3, cccd chip=5, căn cước=6. Selfie strategy_code S0/S5/S7/S9. On success, error_message carries the literal 'thành công'."
        ),
    },
    {
        "id": "ota_travel_rules",
        "title": "OTA (flight/train/bus) business rules",
        "keywords": [
            "ota", "flight", "ve may bay", "train", "tau", "vnr", "bus", "ve xe",
            "booking", "dat ve", "hold seat", "invoice", "hoa don",
        ],
        "content": (
            "OTA rules (PD 213906032): Train providers hold seats for a fixed window, max tickets per passenger limits apply; diacritics are auto-stripped from contact names; duplicate passenger names in one booking are blocked. "
            "Provider errors map to friendly UX copy (e.g., ITEM_TOO_LONG → passenger-name-too-long; NO_FARES → fare changed/sold out). Invoices follow local regulations: issued only at payment time, no re-issue.\n"
            "Bus aggregators: rely on provider-specific payment-confirm APIs (confirm via update with paidMoney — idempotency-sensitive, double-charge risk), booking expiry via overTime races payment latency, company debtLimit can silently block bookings, JWT can expire mid-flow."
        ),
    },
    {
        "id": "incident_patterns",
        "title": "Known production incident patterns (RCAs)",
        "keywords": [
            "incident", "su co", "rca", "outage", "fund loss", "mat tien", "root cause",
            "postmortem", "bai hoc", "lesson", "regression",
        ],
        "content": (
            "Common release risk patterns: (1) untested code refactoring merged to the main branch and deployed alongside unrelated changes — always perform a git diff between the production version and the deploy candidate. "
            "(2) manual configuration changes to settlement delivery paths or schedules without verification — always enforce maker-checker approval. "
            "(3) drop or renaming of callback fields across multiple DTO chains — ensure contract tests are run and deploy services in the correct dependency order. "
            "(4) field renaming breaking existing merchant callbacks — preserve backward compatibility. "
            "(5) dynamic creation of messaging topics or resource leaks — set resource limits and run load tests. "
            "(6) early-return statements in consumers dropping notifications — test negative and timeout paths, and implement dead-letter queues. "
            "(7) duplicate message replay during incident recovery — ensure all replays are idempotent. "
            "(8) incomplete data restore silently truncating values — verify data integrity after restores. "
            "(9) upstream API changes silently removing optional fields — parse responses leniently with fallback defaults. "
            "(10) authentication or verification endpoints susceptible to spam or replay attacks — rate limit and add security checkpoints."
        ),
    },
    {
        "id": "ops_runbooks",
        "title": "Ops runbooks, code freeze, ZNS, deploy, release process",
        "keywords": [
            "code freeze", "tet", "on-call", "oncall", "zns", "deploy", "blue green",
            "k8s", "helm", "regression plan", "release process", "rollout", "canary", "store submit",
        ],
        "content": (
            "Tet code freeze (ZTM 80669290): ~mid-Jan to early Feb for ZPI, Promotion, Lixi, Payment Engine, User Profile, Session, Login, KYC, Risk; exceptions need SRE Manager / Head of PTO approval + announcement to Campaign Monitoring.\n"
            "Mobile release (ZTM 318770321): feature MRs into the release branch ~1 week → bug-fix-only day → final regression → store submit; waiver list needs Squad Lead/PO approval; P0 test cases must pass; cross-platform coverage required. "
            "Server rollout convention: Internal whitelist → Zion whitelist → All users; canary 1% → 10% → 100% with feature flag. Impact Analysis rule: impact spanning >3 domains requires email to ZLP Squad Leaders.\n"
            "ZNS (ZTM 134356586): messages via gRPC cms.messagesystem.v1.MessageReceiver/SendMessage (phone 84xxx, zalo_oa_id + template_id + template_data, requester squad-prefixed).\n"
            "Blue-green deploy (ZTM 67708726): on helm install --wait --timeout 300s --atomic timeout, check k8s events for 'Back-off restarting failed container' or Readiness/Liveness probe failures."
        ),
    },
]


def select_knowledge(message: str, max_blocks: int = 4) -> list[dict]:
    """Chấm điểm block theo số keyword khớp (word-boundary, text đã normalize).

    Fallback: mã lỗi dạng -NNNN trong câu hỏi được dò trực tiếp trong content/keywords
    của block (vd hỏi "-8350" vẫn tìm ra block dù \\b không match trước dấu '-').
    """
    normalized = normalize_vietnamese_text(message.lower())
    error_codes = set(re.findall(r"-\d{2,4}\b", normalized))
    scored: list[tuple[int, dict]] = []
    for block in KNOWLEDGE_BASE:
        score = sum(
            1 for keyword in block["keywords"]
            if re.search(rf"\b{re.escape(keyword)}\b", normalized)
        )
        score += sum(
            1 for code in error_codes
            if code in block["content"] or code in block["keywords"]
        )
        if score > 0:
            scored.append((score, block))
    scored.sort(key=lambda item: -item[0])
    return [block for _, block in scored[:max_blocks]]


def render_knowledge_prompt(message: str, max_blocks: int = 4) -> str:
    """Trả về section kiến thức để nối vào system prompt; rỗng nếu không khớp block nào."""
    blocks = select_knowledge(message, max_blocks=max_blocks)
    if not blocks:
        return ""
    sections = [
        f"### {block['title']}\n{block['content']}" for block in blocks
    ]
    return (
        "\n\nZaloPay reference knowledge relevant to this question "
        "(sourced from internal Confluence ZTM/PD; cite specifics from here when answering):\n"
        + "\n\n".join(sections)
    )
