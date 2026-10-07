"""UPI ID / phone pattern checks and QR payload parsing."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from . import DetectorResult, Reason, noisy_or
from ..brands import detect_brands, load_brands

UPI_FORMAT = re.compile(r"^[a-z0-9][a-z0-9.\-_]{1,63}@[a-z][a-z0-9]{1,30}$")
KNOWN_HANDLES = {
    "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "apl", "upi", "sbi",
    "hdfcbank", "icici", "axisbank", "pnb", "boi", "cnrb", "idfcfirst", "kotak", "yesbank", "unionbank",
    "ikwik", "freecharge", "airtel", "jio", "postbank", "fbl", "rbl", "federal", "indus", "aubank",
}
SCAM_WORDS = ("refund", "support", "care", "helpdesk", "customer", "cashback", "lottery", "reward",
              "claim", "kyc", "prize", "winner", "official", "service")


def analyze_upi(upi_id: str) -> DetectorResult:
    upi = upi_id.strip().lower()
    reasons: list[Reason] = []
    if not UPI_FORMAT.match(upi):
        return DetectorResult("identifier", 0.25,
                              [Reason("bad_upi_format", "This does not look like a valid UPI ID (name@bank).", "identifier", 0.25)])
    user, handle = upi.split("@")
    if handle not in KNOWN_HANDLES:
        reasons.append(Reason("unknown_handle", f"'@{handle}' is not a commonly used UPI bank handle.", "identifier", 0.15))
    words = [w for w in SCAM_WORDS if w in user]
    if words:
        reasons.append(Reason("scammy_name", f"The UPI name contains '{words[0]}', which genuine people rarely use but scammers often do.", "identifier", 0.45))
    brands = detect_brands(re.sub(r"[._\-]", " ", user))
    if brands:
        b = load_brands()[brands[0]]
        reasons.append(Reason("brand_in_upi", f"The UPI name uses '{b.display}', but personal UPI IDs cannot be issued as official bank accounts.", "identifier", 0.45))
    if re.search(r"\d{8,}", user) and not re.fullmatch(r"[6-9]\d{9}", user):
        reasons.append(Reason("long_digits", "The UPI name has a long random digit string.", "identifier", 0.20))
    return DetectorResult("identifier", noisy_or([r.severity for r in reasons]), reasons, {"upi": upi},
                          "fake_upi" if reasons else None)


def analyze_phone(phone: str) -> DetectorResult:
    digits = re.sub(r"\D", "", phone)[-10:]
    reasons: list[Reason] = []
    if len(digits) != 10 or digits[0] not in "6789":
        reasons.append(Reason("bad_phone", "This is not a valid Indian mobile number format.", "identifier", 0.15))
    elif len(set(digits)) <= 3:
        reasons.append(Reason("vanity_phone", "The number has a repetitive pattern, often seen in bulk-registered SIMs.", "identifier", 0.10))
    return DetectorResult("identifier", noisy_or([r.severity for r in reasons]), reasons, {"phone": digits})


def parse_qr_payload(decoded: str) -> dict:
    """Return {'kind': 'upi'|'url'|'text', ...} for a decoded QR string."""
    decoded = decoded.strip()
    if decoded.lower().startswith("upi://"):
        q = {k: v[0] for k, v in parse_qs(urlsplit(decoded).query).items()}
        return {"kind": "upi", "pa": q.get("pa", ""), "pn": q.get("pn", ""), "am": q.get("am"),
                "tn": q.get("tn", ""), "action": urlsplit(decoded).netloc.lower()}
    if re.match(r"^(https?://|www\.)", decoded, re.I):
        return {"kind": "url", "url": decoded}
    return {"kind": "text", "text": decoded}
