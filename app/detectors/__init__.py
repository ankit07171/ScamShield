from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Reason:
    code: str
    text: str
    source: str  # which detector produced it
    severity: float  # 0..1, how strongly it pushes towards "scam"


@dataclass
class DetectorResult:
    name: str  # text | rules | url | identifier | community
    score: float  # 0..1
    reasons: list[Reason] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    scam_type: str | None = None


def noisy_or(values: list[float]) -> float:
    p = 1.0
    for v in values:
        p *= 1.0 - max(0.0, min(1.0, v))
    return 1.0 - p
