"""ScamShield FastAPI gateway: auth, rate limiting, validation, endpoints."""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import community
from .config import get_settings
from .db import Analysis, Entity, Feedback, ModelVersion, Report, SessionLocal, User, get_db, init_db, utcnow
from .detectors.text_classifier import TextClassifier
from .detectors.url_analyzer import UrlAnalyzer
from .infra import Cache, RateLimiter
from .orchestrator import Orchestrator
from .schemas import (AnalysisOut, FeedbackIn, MessageIn, QrIn, ReportIn, ReportStatusIn, UpiIn, UrlIn)
from .util import sha256


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    init_db()
    clf = TextClassifier(s.model_path)
    clf.load()
    with SessionLocal() as db:
        if not db.scalar(select(ModelVersion.id).limit(1)):
            db.add(ModelVersion(metrics=clf.metrics))
            db.commit()
    app.state.orch = Orchestrator(clf, UrlAnalyzer(s.network_enabled, s.whois_enabled), SessionLocal,
                                  Cache(s.redis_url, s.cache_ttl))
    app.state.limiter = RateLimiter(s.redis_url, s.rate_limit_per_minute)
    yield


app = FastAPI(title="ScamShield", version="0.1.0",
              description="UPI and online scam detector. Risk guidance, not certainty.", lifespan=lifespan)


@dataclass
class Principal:
    user_id: int | None
    role: str  # anonymous | user | verified | admin
    key: str


def principal(request: Request, x_api_key: str | None = Header(default=None),
              db: Session = Depends(get_db)) -> Principal:
    s = get_settings()
    client = x_api_key or (request.client.host if request.client else "unknown")
    if not request.app.state.limiter.allow(client):
        raise HTTPException(429, "Rate limit exceeded. Try again in a minute.")
    if x_api_key:
        if x_api_key in s.admin_api_keys:
            return Principal(None, "admin", client)
        if x_api_key in s.api_keys:
            return Principal(None, "user", client)
        user = db.scalar(select(User).where(User.api_key_hash == sha256(x_api_key)))
        if user:
            return Principal(user.id, user.role, client)
    if s.auth_required:
        raise HTTPException(401, "Missing or invalid X-API-Key.")
    return Principal(None, "anonymous", client)


def require_admin(p: Principal = Depends(principal)) -> Principal:
    if p.role != "admin":
        raise HTTPException(403, "Admin only.")
    return p


async def _respond(request: Request, input_type: str, payload: dict, p: Principal, saved_text=None) -> AnalysisOut:
    orch: Orchestrator = request.app.state.orch
    key = sha256(str(payload["reasons"]) + str(payload["score"]) + input_type)  # per-request id, not content
    aid = await asyncio.to_thread(orch.persist, input_type, key, payload, p.user_id, saved_text)
    return AnalysisOut(analysis_id=aid, **payload)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/analyze/message", response_model=AnalysisOut)
async def analyze_message(body: MessageIn, request: Request, p: Principal = Depends(principal)):
    payload = await request.app.state.orch.message(body.text)
    return await _respond(request, "message", payload, p, body.text if body.save_text else None)


@app.post("/v1/analyze/url", response_model=AnalysisOut)
async def analyze_url(body: UrlIn, request: Request, p: Principal = Depends(principal)):
    return await _respond(request, "url", await request.app.state.orch.url(body.url), p)


@app.post("/v1/analyze/upi", response_model=AnalysisOut)
async def analyze_upi(body: UpiIn, request: Request, p: Principal = Depends(principal)):
    return await _respond(request, "upi", await request.app.state.orch.upi(body.upi_id), p)


def _decode_qr_image(b64: str) -> str:
    try:
        import cv2
        import numpy as np
    except ImportError:
        raise HTTPException(501, "QR image decoding needs opencv-python-headless (pip install -r requirements-extras.txt). "
                                 "Send decoded_text instead.")
    try:
        raw = base64.b64decode(b64, validate=False)
        img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    except Exception:
        raise HTTPException(422, "Could not read the image.")
    if not text:
        raise HTTPException(422, "No QR code found in the image.")
    return text


@app.post("/v1/analyze/qr", response_model=AnalysisOut)
async def analyze_qr(body: QrIn, request: Request, p: Principal = Depends(principal)):
    decoded = body.decoded_text or _decode_qr_image(body.image_base64 or "")
    return await _respond(request, "qr", await request.app.state.orch.qr(decoded), p)


@app.post("/v1/reports", status_code=201)
def create_report(body: ReportIn, p: Principal = Depends(principal), db: Session = Depends(get_db)):
    ent = community.get_or_create_entity(db, body.entity_type, body.value)
    if p.user_id is not None and db.scalar(select(Report.id).where(Report.entity_id == ent.id, Report.user_id == p.user_id)):
        raise HTTPException(409, "You have already reported this.")
    db.add(Report(entity_id=ent.id, user_id=p.user_id, reporter_role=p.role, scam_type=body.scam_type,
                  region=body.region, evidence=body.evidence, status="pending"))
    db.flush()
    community.recompute(db, ent)
    db.commit()
    return {"status": "pending", "entity_risk": ent.risk_score,
            "message": "Thanks. Reports are moderated before they carry full weight."}


@app.patch("/v1/reports/{report_id}")
def moderate_report(report_id: int, body: ReportStatusIn, _: Principal = Depends(require_admin),
                    db: Session = Depends(get_db)):
    rep = db.get(Report, report_id)
    if not rep:
        raise HTTPException(404, "Report not found.")
    rep.status = body.status
    e = db.get(Entity, rep.entity_id)
    community.recompute(db, e)
    db.commit()
    return {"id": rep.id, "status": rep.status, "entity_risk": e.risk_score}


@app.get("/v1/reports/trends")
def trends(days: int = 30, db: Session = Depends(get_db)):
    days = max(1, min(days, 365))
    since = utcnow() - timedelta(days=days)
    rows = list(db.scalars(select(Report).where(Report.created_at >= since, Report.status != "rejected")))
    return {
        "window_days": days, "total": len(rows),
        "top_scam_types": Counter(r.scam_type for r in rows).most_common(10),
        "top_regions": Counter(r.region for r in rows if r.region).most_common(10),
        "time_series": sorted(Counter(r.created_at.date().isoformat() for r in rows).items()),
    }


@app.post("/v1/feedback", status_code=201)
def feedback(body: FeedbackIn, db: Session = Depends(get_db), _: Principal = Depends(principal)):
    if not db.get(Analysis, body.analysis_id):
        raise HTTPException(404, "Unknown analysis_id.")
    db.add(Feedback(analysis_id=body.analysis_id, user_label=body.user_label, notes=body.notes))
    db.commit()
    return {"status": "queued_for_review"}
