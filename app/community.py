"""Community reports -> entity reputation (recency- and trust-weighted)."""
from __future__ import annotations

import math
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .brands import SHORTENERS, registered_domain
from .db import Entity, Report, utcnow
from .detectors import DetectorResult, Reason
from .util import normalize_entity, sha256

TRUST = {"admin": 1.0, "verified": 1.0, "user": 0.6, "anonymous": 0.3}
STATUS_WEIGHT = {"verified": 1.0, "pending": 0.4, "rejected": 0.0}
HALF_LIFE_DAYS = 60.0


def canonical(kind: str, value: str) -> tuple[str, str]:
    """URLs on normal domains are tracked per-domain; shortener links are tracked per-URL."""
    if kind in ("url", "domain"):
        v = normalize_entity("url", value)
        host = (urlsplit("http://" + v).hostname or v)
        if kind == "domain" or registered_domain(host) not in SHORTENERS:
            return "domain", normalize_entity("domain", host)
        return "url", v
    return kind, normalize_entity(kind, value)


def get_or_create_entity(db: Session, kind: str, value: str) -> Entity:
    kind, value = canonical(kind, value)
    h = sha256(value)
    ent = db.scalar(select(Entity).where(Entity.type == kind, Entity.value_hash == h))
    if not ent:
        ent = Entity(type=kind, value_hash=h)
        db.add(ent)
        db.flush()
    return ent


def recompute(db: Session, entity: Entity) -> float:
    now = utcnow()
    total = 0.0
    for r in db.scalars(select(Report).where(Report.entity_id == entity.id)):
        age_days = max(0.0, (now - r.created_at).total_seconds() / 86400)
        total += (TRUST.get(r.reporter_role, 0.3) * STATUS_WEIGHT.get(r.status, 0.0)
                  * math.pow(0.5, age_days / HALF_LIFE_DAYS))
    entity.risk_score = round(1 - math.exp(-total / 2.0), 4)
    return entity.risk_score


def lookup(session_factory, kind: str, value: str) -> DetectorResult:
    kind, value = canonical(kind, value)
    with session_factory() as db:
        ent = db.scalar(select(Entity).where(Entity.type == kind, Entity.value_hash == sha256(value)))
        if not ent or ent.risk_score <= 0:
            return DetectorResult("community", 0.0)
        n = len(list(db.scalars(select(Report.id).where(Report.entity_id == ent.id, Report.status != "rejected"))))
        label = {"domain": "domain", "url": "link", "upi": "UPI ID", "phone": "phone number"}[kind]
        return DetectorResult(
            "community", ent.risk_score,
            [Reason("community_reports", f"{n} community report(s) flag this {label} (weighted for recency and reporter trust).",
                    "community", ent.risk_score)],
            {"reports": n, "entity_risk": ent.risk_score}, "reported_entity")
