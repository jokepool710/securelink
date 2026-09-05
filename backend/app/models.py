from pydantic import BaseModel, ConfigDict, Field, StrictBool
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]

class AnalyzeURLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=4096)
    external_intelligence: StrictBool = False

class Evidence(BaseModel):
    id: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    title: str
    explanation: str
    details: dict = Field(default_factory=dict)

class RedirectHop(BaseModel):
    url: str
    host: str
    status_code: int | None = None
    location: str | None = None
    blocked_reason: str | None = None

class ParsedURL(BaseModel):
    scheme: str
    hostname: str
    ascii_hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    username_present: bool

class AnalysisResult(BaseModel):
    submitted_url: str
    parsed: ParsedURL
    risk_level: Literal["low", "medium", "high", "critical"]
    score: int
    recommendation: str
    summary: str
    evidence: list[Evidence]
    redirects: list[RedirectHop]
    dns_addresses: list[str] = []
    tls: dict | None = None
    intelligence: list[dict] = []
    privacy_notice: str

class QRResult(BaseModel):
    payload_type: str
    extracted_content: str
    analysis: AnalysisResult | None = None
