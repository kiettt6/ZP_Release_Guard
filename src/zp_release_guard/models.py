from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zp_release_guard.security import MAX_ANALYSIS_MESSAGE_CHARS, MAX_HINT_CHARS


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Recommendation(str, Enum):
    GO = "Go"
    CONDITIONAL_GO = "Conditional Go"
    NO_GO = "No-Go"


class AnalyzeRequest(StrictBaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_ANALYSIS_MESSAGE_CHARS)
    project_hint: str = Field(default="zalopay", max_length=MAX_HINT_CHARS)
    release_hint: str | None = Field(default=None, max_length=MAX_HINT_CHARS)


class InvocationRequest(StrictBaseModel):
    message: str | None = Field(default=None, max_length=MAX_ANALYSIS_MESSAGE_CHARS)
    input: str | None = Field(default=None, max_length=MAX_ANALYSIS_MESSAGE_CHARS)
    project_hint: str = Field(default="zalopay", max_length=MAX_HINT_CHARS)
    release_hint: str | None = Field(default=None, max_length=MAX_HINT_CHARS)

    @model_validator(mode="after")
    def require_message_or_input(self) -> "InvocationRequest":
        if not (self.message or self.input):
            raise ValueError("message or input is required.")
        return self


class AnalyzeResponse(BaseModel):
    risk_level: RiskLevel
    recommendation: Recommendation
    detected_input_types: list[str]
    markdown_report: str
    warnings: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    source: str
    snippet: str


class Finding(BaseModel):
    title: str
    severity: RiskLevel
    category: str
    rationale: str
    evidence: list[str] = Field(default_factory=list)


class ReleaseContext(BaseModel):
    raw_message: str
    project_hint: str
    release_hint: str | None
    input_sources: list[str]
    domain_signals: list[str]
    evidence: list[Evidence]
