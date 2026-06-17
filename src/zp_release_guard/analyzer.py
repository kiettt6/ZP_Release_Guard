from zp_release_guard.domains import detect_domains
from zp_release_guard.language import clean_latex_symbols, response_language_for
from zp_release_guard.models import AnalyzeResponse, ReleaseContext
from zp_release_guard.parser import collect_evidence, detect_input_types
from zp_release_guard.redaction import redact_sensitive_data
from zp_release_guard.report import recommendation_for, render_markdown_report, rewrite_report_with_llm
from zp_release_guard.risks import detect_risks, overall_risk
from zp_release_guard.security import clean_hint, validate_analysis_text


def analyze_freeform(
    message: str,
    project_hint: str = "zalopay",
    release_hint: str | None = None,
    force_language: str | None = None,
) -> AnalyzeResponse:
    clean_message = clean_latex_symbols(redact_sensitive_data(validate_analysis_text(message)))
    safe_project_hint = clean_hint(project_hint) or "zalopay"
    safe_release_hint = clean_hint(release_hint)
    # force_language ("Vietnamese"/"English") lets the user switch the report language
    # without re-pasting the input (e.g. reply "tiếng việt" to an English report).
    response_language = force_language or response_language_for(clean_message)
    detected_input_types = detect_input_types(clean_message)
    domains = detect_domains(clean_message)
    evidence = collect_evidence(clean_message, detected_input_types)
    findings = detect_risks(clean_message, domains, detected_input_types)
    risk_level = overall_risk(findings)
    recommendation = recommendation_for(risk_level, findings)
    context = ReleaseContext(
        raw_message=clean_message,
        project_hint=safe_project_hint,
        release_hint=safe_release_hint,
        input_sources=detected_input_types,
        domain_signals=domains,
        evidence=evidence,
    )
    report = render_markdown_report(context, findings, risk_level, recommendation, language=response_language)
    report = rewrite_report_with_llm(clean_message, report)
    warnings = []
    if len(clean_message) < 80:
        warnings.append("Input is short; review may miss hidden impacted services, schemas, or partner contracts.")
    return AnalyzeResponse(
        risk_level=risk_level,
        recommendation=recommendation,
        detected_input_types=detected_input_types,
        markdown_report=report,
        warnings=warnings,
    )
