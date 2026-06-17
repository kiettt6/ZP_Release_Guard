from dotenv import load_dotenv
load_dotenv()

import logging
import secrets
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from zp_release_guard.analyzer import analyze_freeform
from zp_release_guard.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    InvocationRequest,
    Recommendation,
    RiskLevel,
    StrictBaseModel,
)
from zp_release_guard.security import (
    MAX_ANALYSIS_MESSAGE_CHARS,
    MAX_UPLOAD_BYTES,
    add_security_headers,
    enforce_access,
    enforce_request_size,
)


# Whitelist of accepted upload formats. Anything else returns 415.
ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}
ALLOWED_TEXT_EXT = {"txt", "md", "json", "py", "diff", "patch", "yml", "yaml", "ini", "log", "csv", "tsv"}
ALLOWED_DOC_EXT = {"pdf", "docx"}
MAX_EXTRACTED_CHARS = MAX_ANALYSIS_MESSAGE_CHARS
MAX_UPLOAD_FILE_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_FILES = 5


logger = logging.getLogger("zp_release_guard.api")


app = FastAPI(title="ZLP ReleaseGuard", version="0.1.0")
# Registration order matters: the LAST registered runs outermost. We want
# add_security_headers outermost so even 401/413/429 responses carry the headers.
app.middleware("http")(enforce_request_size)
app.middleware("http")(enforce_access)
app.middleware("http")(add_security_headers)


class ChatRequest(StrictBaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_ANALYSIS_MESSAGE_CHARS)
    chat_id: int | None = Field(default=None, ge=1, le=2**53 - 1)
    replied_assistant_message: str | None = Field(default=None, max_length=4_000)
    output_language: Literal["default", "Vietnamese", "English"] = "default"


class ChatResponse(BaseModel):
    reply: str
    kind: Literal["chat", "report"]
    chat_id: int
    risk_level: RiskLevel | None = None
    recommendation: Recommendation | None = None
    language: Literal["Vietnamese", "English"]
    extracted_text: str | None = None  # set when reply was produced from an uploaded file
    extracted_chars: int | None = None
    file_name: str | None = None
    file_kind: Literal["image", "pdf", "docx", "text"] | None = None
    file_count: int | None = None
    file_names: list[str] | None = None


def _new_chat_id() -> int:
    # 53-bit so JavaScript Number can represent it without precision loss.
    return secrets.randbits(53) or 1


def _extract_field(markdown: str, prefixes: tuple[str, ...]) -> str | None:
    for line in markdown.splitlines():
        text = line.strip().lstrip("-").lstrip("*").strip()
        for prefix in prefixes:
            if text.lower().startswith(prefix.lower()):
                value = text[len(prefix):].strip()
                if value.startswith(":"):
                    value = value[1:].strip()
                return value
    return None


def _extract_risk_level(markdown: str) -> RiskLevel | None:
    value = _extract_field(markdown, ("Mức rủi ro tổng thể:", "Overall risk:"))
    if not value:
        return None
    lowered = value.lower()
    for level in RiskLevel:
        if lowered.startswith(level.value.lower()):
            return level
    return None


def _extract_recommendation(markdown: str) -> Recommendation | None:
    value = _extract_field(markdown, ("Khuyến nghị:", "Recommendation:"))
    if not value:
        return None
    lowered = value.lower()
    # Longest first so "No-Go" / "Conditional Go" win over "Go".
    for rec in sorted(Recommendation, key=lambda r: -len(r.value)):
        if lowered.startswith(rec.value.lower()):
            return rec
    return None


@app.get("/health")
@app.post("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "zp-release-guard"}


@app.post("/analyze-freeform", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_freeform(
        message=request.message,
        project_hint=request.project_hint,
        release_hint=request.release_hint,
    )


@app.post("/invocations", response_model=AnalyzeResponse)
def invoke(payload: InvocationRequest) -> AnalyzeResponse:
    message = payload.message or payload.input or ""
    if not message.strip():
        raise HTTPException(status_code=422, detail="message or input is required.")
    return analyze_freeform(
        message=message,
        project_hint=payload.project_hint,
        release_hint=payload.release_hint,
    )


class FeedbackRequest(StrictBaseModel):
    rating: Literal["up", "down"]
    chat_id: int | None = Field(default=None, ge=1, le=2**53 - 1)
    note: str | None = Field(default=None, max_length=2_000)


@app.post("/feedback")
def feedback(request: FeedbackRequest) -> dict[str, str]:
    """Lightweight feedback sink — logs 👍/👎 on assistant answers so rules/knowledge can
    be improved over time. Intentionally non-persistent (no PII, no message body)."""
    logger.info("user_feedback rating=%s chat_id=%s note=%s", request.rating, request.chat_id, (request.note or "")[:200])
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """Multi-turn chat endpoint backed by the ReleaseGuard chat engine.

    The client passes a stable `chat_id` to keep conversation context across turns.
    Reply is markdown for QA reports, plain text for follow-up chat / clarification.
    """
    from zp_release_guard.language import response_language_for
    from zp_release_guard.chat_engine import handle_command, is_impact_analysis_report

    chat_id = request.chat_id or _new_chat_id()
    try:
        reply = handle_command(
            request.message,
            chat_id=chat_id,
            replied_assistant_message=request.replied_assistant_message,
            force_language=None if request.output_language == "default" else request.output_language,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    is_report = is_impact_analysis_report(reply)
    # For reports the header is the source of truth; for free chat replies fall
    # back to language detection over the actual reply text.
    if "## Tóm tắt QA" in reply:
        language: Literal["Vietnamese", "English"] = "Vietnamese"
    elif "## QA Review Summary" in reply:
        language = "English"
    else:
        language = "Vietnamese" if response_language_for(reply) == "Vietnamese" else "English"

    return ChatResponse(
        reply=reply,
        kind="report" if is_report else "chat",
        chat_id=chat_id,
        risk_level=_extract_risk_level(reply) if is_report else None,
        recommendation=_extract_recommendation(reply) if is_report else None,
        language=language,
    )


def _file_extension(filename: str | None) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _is_image(mime: str, ext: str) -> bool:
    return mime.startswith("image/") or ext in ALLOWED_IMAGE_EXT


def _extract_text_from_upload(
    filename: str | None,
    mime: str,
    contents: bytes,
) -> tuple[str, Literal["image", "pdf", "docx", "text"]]:
    """Route an uploaded file to the right extractor. Raises HTTPException on failure."""
    from zp_release_guard.chat_engine import (
        extract_text_from_docx,
        extract_text_from_pdf,
        transcribe_image_with_llm,
    )

    ext = _file_extension(filename)
    if _is_image(mime, ext):
        text = transcribe_image_with_llm(contents, mime or "image/jpeg")
        if text.startswith("Error transcribing image: the vision model"):
            # Vision model not configured — return a placeholder so other files still process
            return f"[Ảnh: {filename or 'attachment'} — OCR không khả dụng (chưa cấu hình vision model)]", "image"
        if text.startswith("Error"):
            raise HTTPException(status_code=422, detail=text)
        return text, "image"
    if mime == "application/pdf" or ext == "pdf":
        try:
            text = extract_text_from_pdf(contents)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Cannot read PDF: {exc}") from exc
        return text, "pdf"
    if ext == "docx" or "wordprocessingml" in mime:
        try:
            text = extract_text_from_docx(contents)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Cannot read DOCX: {exc}") from exc
        return text, "docx"
    if ext in ALLOWED_TEXT_EXT or mime.startswith("text/"):
        try:
            text = contents.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=415, detail="File is not valid UTF-8 text.") from exc
        return text, "text"
    raise HTTPException(
        status_code=415,
        detail="Unsupported file type. Allowed: image (jpg/png/webp/…), PDF, DOCX, or UTF-8 text.",
    )


def _combine_uploaded_texts(parts: list[tuple[str, str, str]]) -> str:
    blocks = []
    for index, (filename, file_kind, extracted) in enumerate(parts, start=1):
        blocks.append(
            f"### File {index}: {filename} ({file_kind})\n"
            f"{extracted.strip()}"
        )
    return "\n\n".join(blocks)


@app.post("/chat-upload", response_model=ChatResponse)
async def chat_upload(
    files: list[UploadFile] | None = File(default=None),
    file: UploadFile | None = File(default=None),
    message: str = Form(""),
    chat_id: int | None = Form(default=None),
    output_language: Literal["default", "Vietnamese", "English"] = Form("default"),
) -> ChatResponse:
    """Multipart endpoint for one or more image / PDF / DOCX / text uploads.

    Like /chat, uploads run through the deterministic 11-section template analyzer
    so a file produces the same full QA report (risk matrix, P0/P1 checklist, dev
    questions, Go/No-Go) as pasted text — the extracted/OCR'd text is fed straight
    into analyze_freeform.
    """
    from fastapi.concurrency import run_in_threadpool

    from zp_release_guard.language import response_language_for
    from zp_release_guard.chat_engine import analyze_and_track, is_impact_analysis_report

    upload_files = list(files or [])
    if file is not None:
        upload_files.append(file)
    if not upload_files:
        raise HTTPException(status_code=422, detail="At least one file is required.")
    if len(upload_files) > MAX_UPLOAD_FILES:
        raise HTTPException(status_code=413, detail=f"Too many files (max {MAX_UPLOAD_FILES}).")

    if chat_id is not None and not (1 <= chat_id <= 2**53 - 1):
        raise HTTPException(status_code=422, detail="Invalid chat_id.")

    extracted_parts: list[tuple[str, str, str]] = []
    total_raw_bytes = 0

    for upload in upload_files:
        contents = await upload.read()
        if not contents:
            raise HTTPException(status_code=422, detail=f"Empty file: {upload.filename or 'attachment'}.")
        if len(contents) > MAX_UPLOAD_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large: {upload.filename or 'attachment'} (max {MAX_UPLOAD_FILE_BYTES // (1024 * 1024)}MB each).",
            )
        total_raw_bytes += len(contents)
        if total_raw_bytes > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Total upload too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)}MB).",
            )

        extracted, file_kind = await run_in_threadpool(
            _extract_text_from_upload, upload.filename, upload.content_type or "", contents
        )
        extracted = extracted.strip()
        if not extracted:
            raise HTTPException(status_code=422, detail=f"Could not extract any text from: {upload.filename or 'attachment'}.")
        extracted_parts.append((upload.filename or "attachment", file_kind, extracted))

    extracted = extracted_parts[0][2] if len(extracted_parts) == 1 else _combine_uploaded_texts(extracted_parts)
    if len(extracted) > MAX_EXTRACTED_CHARS:
        extracted = extracted[:MAX_EXTRACTED_CHARS]

    first_kind = extracted_parts[0][1]
    file_kind: Literal["image", "pdf", "docx", "text"] = (
        first_kind if len({part[1] for part in extracted_parts}) == 1 else "text"
    )  # mixed uploads are presented as combined text context
    file_names = [part[0] for part in extracted_parts]
    file_label = file_names[0] if len(file_names) == 1 else f"{len(file_names)} attachments"

    # File parsing/OCR and the LLM call are blocking (requests, pypdf, python-docx).
    # This handler is async, so run them in the threadpool — otherwise a single slow
    # upload (LLM up to 90s) would block the whole event loop and stall every request.
    user_prompt = (message or "").strip()
    forced_language: Literal["Vietnamese", "English"] | None = (
        None if output_language == "default" else output_language
    )
    # Feed the extracted/OCR'd text (plus any user instruction) into the same
    # deterministic analyzer the typed-text path uses, so files get the full report.
    text_to_analyze = f"{user_prompt}\n\n{extracted}" if user_prompt else extracted
    user_label = f"[Upload: {file_label}] {user_prompt}".strip()

    cid = chat_id or _new_chat_id()
    try:
        # analyze_freeform is CPU-bound (regex/template) but may invoke an optional
        # LLM rewrite; run in the threadpool so it never freezes the event loop.
        reply = await run_in_threadpool(
            analyze_and_track, text_to_analyze, cid, forced_language, None, user_label
        )
    except Exception as exc:  # network / LLM errors
        raise HTTPException(status_code=502, detail=f"LLM error: {exc}") from exc

    is_report = is_impact_analysis_report(reply)
    if "## Tóm tắt QA" in reply:
        language: Literal["Vietnamese", "English"] = "Vietnamese"
    elif "## QA Review Summary" in reply:
        language = "English"
    else:
        language = "Vietnamese" if response_language_for(reply) == "Vietnamese" else "English"

    return ChatResponse(
        reply=reply,
        kind="report" if is_report else "chat",
        chat_id=cid,
        risk_level=_extract_risk_level(reply) if is_report else None,
        recommendation=_extract_recommendation(reply) if is_report else None,
        language=language,
        extracted_text=extracted,
        extracted_chars=len(extracted),
        file_name=file_label,
        file_kind=file_kind,
        file_count=len(extracted_parts),
        file_names=file_names,
    )


# Static web UI — must be mounted AFTER all API routes so they win route matching.
_WEB_DIR = Path(__file__).resolve().parent / "web"
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
