from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    language: str | None = Field(default=None, max_length=10)
    save_text: bool = Field(default=False, description="Opt in to storing the raw text. Off by default.")


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class UpiIn(BaseModel):
    upi_id: str = Field(min_length=3, max_length=256)


class QrIn(BaseModel):
    decoded_text: str | None = Field(default=None, max_length=2048)
    image_base64: str | None = Field(default=None, max_length=8_000_000)

    @model_validator(mode="after")
    def _one(self):
        if not self.decoded_text and not self.image_base64:
            raise ValueError("Provide decoded_text or image_base64")
        return self


class ReasonOut(BaseModel):
    code: str
    text: str
    source: str
    severity: float


class EducationOut(BaseModel):
    scam_type: str | None
    title: str
    what_to_do: list[str]


class AnalysisOut(BaseModel):
    analysis_id: int
    verdict: Literal["Safe", "Suspicious", "High risk"]
    score: float
    reasons: list[ReasonOut]
    scam_type: str | None
    advice: list[str]
    education: EducationOut | None
    detectors: dict[str, float]
    model_version: str
    disclaimer: str


class ReportIn(BaseModel):
    entity_type: Literal["url", "domain", "upi", "phone"]
    value: str = Field(min_length=3, max_length=2048)
    scam_type: str = Field(min_length=2, max_length=40)
    evidence: str | None = Field(default=None, max_length=2000)
    region: str | None = Field(default=None, max_length=64)


class ReportStatusIn(BaseModel):
    status: Literal["pending", "verified", "rejected"]


class FeedbackIn(BaseModel):
    analysis_id: int
    user_label: Literal["safe", "suspicious", "high_risk"]
    notes: str | None = Field(default=None, max_length=1000)
