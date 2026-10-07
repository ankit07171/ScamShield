"""Score aggregation: weighted noisy-OR across detectors -> verdict + explanation.

Start here, then replace with a gradient-boosted meta-model trained on detector outputs and
calibrate it (isotonic/Platt) so that 'score 80' really means ~80% of such cases are scams.
"""
from __future__ import annotations

from .detectors import DetectorResult, Reason, noisy_or

WEIGHTS = {"text": 0.85, "rules": 1.0, "url": 0.9, "identifier": 0.9, "community": 1.0}
SUSPICIOUS_AT = 0.30
HIGH_RISK_AT = 0.65
MAX_REASONS = 6


def verdict_for(p: float) -> str:
    return "High risk" if p >= HIGH_RISK_AT else "Suspicious" if p >= SUSPICIOUS_AT else "Safe"


def aggregate(results: list[DetectorResult]) -> dict:
    contributions = [r.score * WEIGHTS.get(r.name, 0.8) for r in results]
    p = noisy_or(contributions)
    per_detector: dict[str, float] = {}
    for r in results:
        per_detector[r.name] = max(per_detector.get(r.name, 0.0), round(r.score, 3))

    reasons: list[Reason] = []
    seen: set[str] = set()
    for rs in sorted((x for r in results for x in r.reasons), key=lambda x: -x.severity):
        if rs.code not in seen and rs.severity > 0:
            seen.add(rs.code)
            reasons.append(rs)
    reasons = reasons[:MAX_REASONS]

    typed = [(r.score, r.scam_type) for r in results if r.scam_type]
    scam_type = max(typed, key=lambda t: t[0])[1] if typed and p >= SUSPICIOUS_AT else None

    verdict = verdict_for(p)
    if not reasons and verdict == "Safe":
        reasons = [Reason("no_signals", "No known scam patterns were found in this input.", "aggregator", 0.0)]
    return {"score": round(p * 100, 1), "verdict": verdict, "reasons": reasons,
            "scam_type": scam_type, "detectors": per_detector}
