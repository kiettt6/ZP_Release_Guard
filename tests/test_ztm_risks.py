# Tests cho các rule/domain/parser học từ Confluence space ZTM
# (templates, RCA thực tế, EA docs). Mỗi rule có 1 case trigger và 1 case mitigated.

from zp_release_guard.domains import detect_domains
from zp_release_guard.parser import detect_input_types
from zp_release_guard.risks import detect_risks


def _titles(msg: str) -> list[str]:
    return [f.title for f in detect_risks(msg, ["general_release_change"], ["release_note"])]


# =============================================================================
# Risk rules
# =============================================================================

def test_settlement_file_delivery_rule():
    # Rule: file settlement and delivery config change verification
    title = "Settlement file or delivery config change lacks maker-checker and merchant verification."
    msg = "Update delivery config for merchant settlement file to a new SFTP folder."
    assert title in _titles(msg)

    msg_mitigated = (
        "Update delivery config for merchant settlement file. "
        "Maker checker approval ticket created and merchant confirmation received."
    )
    assert title not in _titles(msg_mitigated)


def test_callback_dto_field_rule():
    # Rule: callback payload/DTO mapping compatibility
    title = "Callback/DTO field change lacks backward compatibility and contract test coverage."
    msg = "Add new field bankReturnCode to bank callback payload and update DTO mapping."
    assert title in _titles(msg)

    msg_mitigated = (
        "Add new field bankReturnCode to bank callback payload. "
        "Contract test added and change is backward compatible, support both versions."
    )
    assert title not in _titles(msg_mitigated)


def test_refactor_ride_along_rule():
    # Rule: refactored or long-lived code review
    title = "Refactored or long-lived code may ride along on this release without scope review."
    msg = "Refactor repayment flow, code already on main from last month."
    assert title in _titles(msg)

    msg_mitigated = (
        "Refactor repayment flow. Git diff review completed between prod version "
        "and deploy candidate, qa sign-off done."
    )
    assert title not in _titles(msg_mitigated)


def test_replay_backfill_idempotency_rule():
    # Rule: replay/repush/backfill operations idempotency check
    title = "Replay/repush/backfill operation lacks an idempotency or double-payout guard."
    msg = "Backfill missing refund records and repush settlement messages to partner."
    assert title in _titles(msg)

    msg_mitigated = (
        "Backfill missing refund records, repush is idempotent with duplicate check "
        "against settled records."
    )
    assert title not in _titles(msg_mitigated)


def test_external_dependency_failover_rule():
    # Rule: external dependency verification
    title = "External dependency added or changed without failover or circuit breaker."
    msg = "Integrate external sdk loaded from cdn for tracking on the binding page."
    assert title in _titles(msg)

    msg_mitigated = (
        "Integrate external sdk for tracking, self-host the bundle with a local fallback."
    )
    assert title not in _titles(msg_mitigated)


def test_multi_service_deploy_order_rule():
    # Rule: multi-service or shared-library deploy order
    title = "Multi-service or shared-library release lacks an explicit deployment order."
    msg = "Bump version of shared lib used by bc-bank-receiver and bc-api."
    assert title in _titles(msg)

    msg_mitigated = (
        "Bump version of shared lib. Deploy order documented: shared-lib then receiver "
        "then api, verify in staging first."
    )
    assert title not in _titles(msg_mitigated)


def test_consumer_notification_negative_path_rule():
    # Rule: message consumer or notification negative path testing
    title = "Message consumer or merchant notification change lacks negative-path test and DLQ handling."
    msg = "Change kafka consumer to notify merchant on order success."
    assert title in _titles(msg)

    msg_mitigated = (
        "Change kafka consumer to notify merchant. Added dead letter queue and "
        "negative test covering pending and failed orders."
    )
    assert title not in _titles(msg_mitigated)


def test_restore_validation_rule():
    # Rule: data restore validation
    title = "Data restore from backup lacks post-restore validation."
    msg = "Restore backup of etcd app-info data after the incident."
    assert title in _titles(msg)

    msg_mitigated = (
        "Restore backup of etcd app-info data, then run data validation and "
        "verify random sample after restore."
    )
    assert title not in _titles(msg_mitigated)


def test_visa_mti_idempotency_rule():
    # [EA][2025] Idempotency & Duplication: MTI 0x00 exactly-once, advice 0x20 dedup
    title = "Visa/Tap2Pay MTI processing change lacks exactly-once and advice-dedup guarantees."
    msg = "Handle new MTI 0220 advice message from Pismo for Tap2Pay clearing."
    assert title in _titles(msg)

    msg_mitigated = (
        "Handle new MTI 0220 advice message with idempotency on bcTransID, "
        "at most one advice applied per payment."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_escrow_balance_rule():
    # -5000 escrow account hết số dư làm fail mọi giao dịch qua connector
    title = "Bank Connector escrow/guarantee account balance is not monitored."
    msg = "Switch disbursement to use the new wallet escrow account for IBFT payout."
    assert title in _titles(msg)

    msg_mitigated = (
        "Switch disbursement to the new wallet escrow account; "
        "balance monitor and alert threshold on escrow balance query added."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_return_code_mapping_rule():
    title = "Bank return-code mapping is not updated for new or changed bank codes."
    msg = "Connector converter handles a new error code from the bank response."
    assert title in _titles(msg)

    msg_mitigated = (
        "Connector converter handles a new bank response code; "
        "mapping table updated in bcadm with a default code fallback."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_new_bank_config_rule():
    title = "New bank/connector config (bankFunction, BankInfo, BankConfig) may be missing."
    msg = "Integrate a new bank connector with bankFunction for link and withdraw."
    assert title in _titles(msg)

    msg_mitigated = (
        "Integrate a new bank connector; bankFunction config added on CDN tool "
        "and verified with cache reload in every environment."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_callback_idempotency_rule():
    title = "Inbound bank callback handling lacks idempotency/dedup."
    msg = "Update bankqrreceiver to process the RBA callback from the bank."
    assert title in _titles(msg)

    msg_mitigated = (
        "Update bankqrreceiver for the RBA callback; idempotency check via "
        "bcidempotencylog with duplicate check on trace no."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_sync_queue_stall_rule():
    title = "Synchronous bank-call path can stall the shared queue (no slow-bank isolation)."
    msg = "Add a synchronous connector call to the bank in the proxy hop."
    assert title in _titles(msg)

    msg_mitigated = (
        "Add a connector call using the async V3.1 flow with per-bank rate limit "
        "and a transaction expired message for queue isolation."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_single_bank_failover_rule():
    title = "Single-bank or single-QR-route dependency lacks a maintenance/failover path."
    msg = "Route VietQR Dong through a single bank as the primary bank."
    assert title in _titles(msg)

    msg_mitigated = (
        "Route VietQR Dong through the primary bank with a failover to switch bank "
        "to Ban Viet and a maintenance scenario via BAM object."
    )
    assert title not in _titles(msg_mitigated)


def test_bc_domain_detection():
    assert "bank_connector" in detect_domains("Deploy bc-api to handle IBFT disbursement via escrow account")
    assert "bank_connector" in detect_domains("Cập nhật returncodemapping cho bankqrreceiver xử lý RBA callback")


def test_unbounded_resource_rule():
    # Rule: unbounded resource limits and testing
    title = "Unbounded resource creation (dynamic topics, goroutines, connections) lacks load testing and limits."
    msg = "Create topic per cashier and spawn one goroutine per websocket session."
    assert title in _titles(msg)

    msg_mitigated = (
        "Create topic per cashier with resource limit, connection pool, "
        "and load test executed before rollout."
    )
    assert title not in _titles(msg_mitigated)


# =============================================================================
# Domain detection
# =============================================================================

def test_ztm_domain_detection():
    assert "tap2pay_card_processing" in detect_domains("Release Tap2Pay clearing flow with Pismo")
    assert "installment_paylater" in detect_domains("Cập nhật luồng gạch nợ ngân hàng đối tác cho PayLater")
    assert "agreement_autopay" in detect_domains("Autopay binding with pay token for partner app")
    assert "bank_connector" in detect_domains("Deploy bc-api to handle VietQR virtual account")
    assert "bus_ticketing_travel" in detect_domains("AnVui bus ticketing integration plan")
    assert "mobile_release_regression" in detect_domains("Final regression for candidate build v11.8.0")


def test_ztm_domains_feed_baseline_findings():
    findings = detect_risks(
        "Chuẩn bị release tap2pay clearing.",
        ["tap2pay_card_processing"],
        ["release_note"],
    )
    assert any(f.category == "Domain impact" for f in findings)


# =============================================================================
# Input-type detection theo template ZTM
# =============================================================================

def test_detect_change_request_doc():
    msg = "Change Request\nContext: ...\nRequirement (CHOOSE 1 FROM 3)\nAcceptance Criteria: ..."
    assert "change_request_doc" in detect_input_types(msg)


def test_detect_merge_request_doc():
    msg = "1. Purpose & Motivation (Why)\n2. Key Changes (What)\n3. Verification & Testing (How)"
    assert "merge_request_doc" in detect_input_types(msg)


def test_detect_rca_incident_doc():
    msg = "Incident Summary\nEvent Timeline\nBusiness Impact\nRoot Cause\nFollow up actions"
    assert "rca_incident_doc" in detect_input_types(msg)


def test_detect_rollout_checklist():
    msg = "Rollout Checklist\nI. Service Dependencies\nII. Deployment Steps\nCICD Ticket: ..."
    assert "rollout_checklist" in detect_input_types(msg)


def test_detect_impact_analysis_vietnamese():
    msg = "1. Tổng quan\n2. Tác động kỹ thuật\n3. Đánh giá rủi ro\n5. Thu hồi & Giám sát"
    assert "impact_analysis_doc" in detect_input_types(msg)
