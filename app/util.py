"""Extraction and hashing helpers."""
from __future__ import annotations

import hashlib
import re

_TLDS = ("com|in|net|org|co|xyz|top|click|work|live|icu|buzz|cfd|sbs|vip|site|online|shop|club|link|"
         "rest|monster|cyou|info|biz|app|me|io|ly|gl|cc|tk|ml|ga|cf|gq|gov|edu|ai|store|tech|page|pw|cn|ru")
URL_RE = re.compile(
    rf"(?:https?://[^\s<>\"'()]+)|(?:www\.[^\s<>\"'()]+)|"
    rf"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{_TLDS})(?![a-z0-9.-])(?:/[^\s<>\"'()]*)?",
    re.I,
)
UPI_RE = re.compile(r"(?<![\w.-])[a-z0-9][a-z0-9.\-_]{1,63}@[a-z][a-z0-9]{1,30}(?![\w.])", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}\"'")
        if u and u.lower() not in (s.lower() for s in seen):
            seen.append(u)
    return seen


def extract_upis(text: str) -> list[str]:
    # An email has a dot in its domain part; a UPI handle (okaxis, ybl, paytm...) does not.
    return list(dict.fromkeys(m.group(0).lower() for m in UPI_RE.finditer(text)))


def extract_phones(text: str) -> list[str]:
    return list(dict.fromkeys(normalize_phone(m.group(0)) for m in PHONE_RE.finditer(text)))


def normalize_phone(p: str) -> str:
    digits = re.sub(r"\D", "", p)
    return digits[-10:]


def normalize_entity(kind: str, value: str) -> str:
    v = value.strip().lower()
    if kind == "phone":
        return normalize_phone(v)
    if kind == "domain":
        v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
        return v.removeprefix("www.").strip(".")
    if kind == "url":
        v = re.sub(r"^https?://", "", v).removeprefix("www.")
        return v.rstrip("/")
    return v
