"""Brand knowledge: official domains, claimed-brand detection, domain helpers."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
MULTI_SUFFIXES = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "res.in", "edu.in",
                  "co.uk", "org.uk", "com.au", "co.za"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "ow.ly", "buff.ly", "t.ly", "tiny.cc", "rebrand.ly", "bitly.com", "s.id", "v.gd"}


@dataclass(frozen=True)
class Brand:
    key: str
    display: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]

    @property
    def single_aliases(self) -> tuple[str, ...]:
        return tuple(a for a in self.aliases if " " not in a)


@lru_cache
def load_brands() -> dict[str, Brand]:
    raw = json.loads((DATA / "brands.json").read_text(encoding="utf-8"))
    return {k: Brand(k, v["display"], tuple(v["aliases"]), tuple(v["domains"])) for k, v in raw.items()}


@lru_cache
def _alias_patterns() -> list[tuple[str, re.Pattern]]:
    out = []
    for b in load_brands().values():
        for a in b.aliases:
            out.append((b.key, re.compile(rf"(?<![a-z0-9]){re.escape(a)}(?![a-z0-9])", re.I)))
    return out


def detect_brands(text: str) -> list[str]:
    """Brands the message *claims* to come from / talks about."""
    found: list[str] = []
    for key, pat in _alias_patterns():
        if key not in found and pat.search(text):
            found.append(key)
    return found


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_official(host: str, brand: Brand) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in brand.domains)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def deobfuscate(label: str) -> str:
    """Undo common homoglyph tricks: amaz0n -> amazon, rnicrosoft -> microsoft."""
    return (label.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
            .replace("rn", "m").replace("vv", "w"))
