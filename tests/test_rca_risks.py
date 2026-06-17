from zp_release_guard.risks import detect_risks, RISK_RULES

def test_installment_mismatch_rule():
    # Trigger
    msg = "Release installment feature for Paylater, partner bank repayment flow. Gach no customer balance."
    findings = detect_risks(msg, ["merchant_payment"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Installment repayment and partner debt settlement status mismatch." in titles

    # Mitigated
    msg_mitigated = "Release installment feature for Paylater, partner bank repayment. Check status of payment first before calling gach no to verify payment status."
    findings_m = detect_risks(msg_mitigated, ["merchant_payment"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Installment repayment and partner debt settlement status mismatch." not in titles_m

def test_duplicate_transid_rule():
    # Trigger
    msg = "Deploy bc-api, sinh ma transid using sequence count generator."
    findings = detect_risks(msg, ["bank_linking"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Stale replica or sequence count causing duplicate transaction IDs (TransID)." in titles

    # Mitigated
    msg_mitigated = "Deploy bc-api, sinh ma transid. Validate transaction info and verify amount match to check user id on duplicate."
    findings_m = detect_risks(msg_mitigated, ["bank_linking"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Stale replica or sequence count causing duplicate transaction IDs (TransID)." not in titles_m

def test_refund_cancel_opt_rule():
    # Trigger
    msg = "Gop code refund and cancel into a single function to optimize code."
    findings = detect_risks(msg, ["refund"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Merging Refund and Cancel logic leading to full refund on partial requests." in titles

    # Mitigated
    msg_mitigated = "Gop code refund and cancel, but write partial test and verify refund amount with balance check."
    findings_m = detect_risks(msg_mitigated, ["refund"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Merging Refund and Cancel logic leading to full refund on partial requests." not in titles_m

def test_refactor_auto_query_rule():
    # Trigger
    msg = "Refactor shared event parser for bill-event in storage."
    findings = detect_risks(msg, ["settlement_reconciliation"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Refactoring shared event parser or DTO without validation of automated/scheduled pipelines." in titles

    # Mitigated
    msg_mitigated = "Refactor shared event parser for bill-event. Add regression test auto to verify all pipelines for both manual and auto."
    findings_m = detect_risks(msg_mitigated, ["settlement_reconciliation"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Refactoring shared event parser or DTO without validation of automated/scheduled pipelines." not in titles_m

def test_json_case_sensitivity_rule():
    # Trigger
    msg = "Update configs on remote config for rollout percent of Toro."
    findings = detect_risks(msg, ["risk_fraud"], ["release_note"])
    titles = [f.title for f in findings]
    assert "JSON configuration key case-sensitivity mismatch in rollout settings." in titles

    # Mitigated
    msg_mitigated = "Update configs for rollout percent. Schema validation is added to validate json keys during deserialization test."
    findings_m = detect_risks(msg_mitigated, ["risk_fraud"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "JSON configuration key case-sensitivity mismatch in rollout settings." not in titles_m

def test_mobile_nfc_permission_rule():
    # Trigger
    msg = "Add uses-feature and permissions in Android manifest for ekyc NFC requirements."
    findings = detect_risks(msg, ["kyc_account_status"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Mobile app uses-feature or permission changes restricting device compatibility." in titles

    # Mitigated
    msg_mitigated = "Add uses-feature for NFC. Run compatibility check and verify device compatibility with negative hardware test."
    findings_m = detect_risks(msg_mitigated, ["kyc_account_status"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Mobile app uses-feature or permission changes restricting device compatibility." not in titles_m

def test_micro_app_onresume_rule():
    # Trigger
    msg = "Change native reload container code to reuse micro-app instance."
    findings = detect_risks(msg, ["merchant_payment"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Stale parameters persistence in micro-app container due to state reuse." in titles

    # Mitigated
    msg_mitigated = "Change native container to reuse micro-app instance. We implement onResume handler to clear state and reset parameters."
    findings_m = detect_risks(msg_mitigated, ["merchant_payment"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Stale parameters persistence in micro-app container due to state reuse." not in titles_m

def test_partner_spec_changes_rule():
    # Trigger
    msg = "Deploy spec change in partner bank connector for OTP bypass."
    findings = detect_risks(msg, ["bank_linking"], ["release_note"])
    titles = [f.title for f in findings]
    assert "Third-party bank connector spec changes or missed error code mapping." in titles

    # Mitigated
    msg_mitigated = "Deploy partner spec change. Performed spec alignment, added reconciliation mapping and verified error code test."
    findings_m = detect_risks(msg_mitigated, ["bank_linking"], ["release_note"])
    titles_m = [f.title for f in findings_m]
    assert "Third-party bank connector spec changes or missed error code mapping." not in titles_m
