"""Runs the detectors in parallel (asyncio) and builds the final verdict."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from urllib.parse import urlsplit

from . import community
from .aggregator import aggregate
from .brands import detect_brands
from .db import Analysis
from .detectors import DetectorResult, Reason, noisy_or
from .detectors import identifier, rules
from .detectors.text_classifier import TextClassifier
from .detectors.url_analyzer import UrlAnalyzer, normalize_url
from .education import card_for
from .infra import Cache
from .util import extract_phones, extract_upis, extract_urls, sha256

DISCLAIMER = ("ScamShield gives risk guidance, not certainty. Never share your PIN or OTP, "
              "and verify through your bank's official app or website.")
ADVICE = {
    "Safe": ["No scam signals found, but stay cautious with unexpected requests for money or codes."],
    "Suspicious": ["Do not click links or pay anything yet.", "Verify using the official app, website or number you look up yourself."],
    "High risk": ["Do not click, reply, pay or share any code.", "Block the sender; if you already acted, call your bank and dial 1930."],
}
MAX_ENTITIES = 3


class Orchestrator:
    def __init__(self, classifier: TextClassifier, url_analyzer: UrlAnalyzer, session_factory,
                 cache: Cache, model_version: str = "baseline-v1"):
        self.clf, self.urls, self.sf, self.cache = classifier, url_analyzer, session_factory, cache
        self.model_version = model_version

    # -------- helpers --------
    def _finish(self, input_type: str, key: str, results: list[DetectorResult]) -> dict:
        agg = aggregate(results)
        payload = {
            "verdict": agg["verdict"], "score": agg["score"],
            "reasons": [asdict(r) for r in agg["reasons"]],
            "scam_type": agg["scam_type"], "advice": ADVICE[agg["verdict"]],
            "education": card_for(agg["scam_type"]) if agg["verdict"] != "Safe" else None,
            "detectors": agg["detectors"], "model_version": self.model_version,
            "disclaimer": DISCLAIMER,
        }
        self.cache.set(f"analysis:{input_type}:{key}", payload)
        return payload

    def persist(self, input_type: str, key: str, payload: dict, user_id: int | None,
                saved_text: str | None = None) -> int:
        with self.sf() as db:
            row = Analysis(user_id=user_id, input_type=input_type, input_hash=key, score=payload["score"],
                           verdict=payload["verdict"], reasons=payload["reasons"], saved_text=saved_text)
            db.add(row)
            db.commit()
            return row.id

    def _cached(self, input_type: str, key: str) -> dict | None:
        return self.cache.get(f"analysis:{input_type}:{key}")

    async def _gather(self, jobs: list) -> list[DetectorResult]:
        return list(await asyncio.gather(*jobs))

    # -------- public analyzers --------
    async def message(self, text: str) -> dict:
        key = sha256(text.strip())
        if (c := self._cached("message", key)):
            return c
        urls = extract_urls(text)[:MAX_ENTITIES]
        upis = extract_upis(text)[:MAX_ENTITIES]
        phones = extract_phones(text)[:MAX_ENTITIES]
        brands = detect_brands(text)
        jobs = [asyncio.to_thread(self.clf.analyze, text), asyncio.to_thread(rules.evaluate, text)]
        for u in urls:
            jobs.append(asyncio.to_thread(self.urls.analyze, u, brands))
            jobs.append(asyncio.to_thread(community.lookup, self.sf, "url", normalize_url(u)))
        for u in upis:
            jobs += [asyncio.to_thread(identifier.analyze_upi, u),
                     asyncio.to_thread(community.lookup, self.sf, "upi", u)]
        for p in phones:
            jobs += [asyncio.to_thread(identifier.analyze_phone, p),
                     asyncio.to_thread(community.lookup, self.sf, "phone", p)]
        results = await self._gather(jobs)
        return self._finish("message", key, results)

    async def url(self, url: str) -> dict:
        key = sha256(url.strip().lower())
        if (c := self._cached("url", key)):
            return c
        results = await self._gather([
            asyncio.to_thread(self.urls.analyze, url, ()),
            asyncio.to_thread(community.lookup, self.sf, "url", normalize_url(url)),
        ])
        return self._finish("url", key, results)

    async def upi(self, upi_id: str) -> dict:
        key = sha256(upi_id.strip().lower())
        if (c := self._cached("upi", key)):
            return c
        results = await self._gather([
            asyncio.to_thread(identifier.analyze_upi, upi_id),
            asyncio.to_thread(community.lookup, self.sf, "upi", upi_id),
        ])
        return self._finish("upi", key, results)

    async def qr(self, decoded: str) -> dict:
        parsed = identifier.parse_qr_payload(decoded)
        if parsed["kind"] == "url":
            res = await self.url(parsed["url"])
            return res
        if parsed["kind"] == "text":
            return await self.message(parsed["text"])
        key = sha256(decoded.strip())
        if (c := self._cached("qr", key)):
            return c
        pa = parsed["pa"]
        extra: list[Reason] = []
        if parsed["am"]:
            extra.append(Reason("qr_has_amount", "This QR will SEND money: scanning a QR code can only pay, never receive. "
                                "Anyone who asks you to scan a QR to 'receive' money is scamming you.", "identifier", 0.35))
        tn_hit = rules.evaluate(parsed["tn"]) if parsed["tn"] else None
        jobs = [asyncio.to_thread(identifier.analyze_upi, pa), asyncio.to_thread(community.lookup, self.sf, "upi", pa)]
        results = await self._gather(jobs)
        if extra:
            results.append(DetectorResult("identifier", noisy_or([r.severity for r in extra]), extra, {}, "collect_request"))
        if tn_hit:
            results.append(tn_hit)
        return self._finish("qr", key, results)
