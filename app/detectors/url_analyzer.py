"""URL analysis: static lexical/brand checks + optional sandboxed redirect following + WHOIS."""
from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from ..brands import (SHORTENERS, deobfuscate, is_official, levenshtein, load_brands, registered_domain)
from . import DetectorResult, Reason, noisy_or

SUSPICIOUS_TLDS = {"xyz", "top", "click", "work", "live", "icu", "buzz", "cfd", "sbs", "vip", "site",
                   "online", "shop", "club", "link", "rest", "monster", "cyou", "fit", "loan",
                   "gq", "tk", "ml", "ga", "cf", "pw"}
KEYWORDS = {"kyc", "verify", "update", "secure", "login", "refund", "reward", "claim", "bonus",
            "suspend", "blocked", "unlock", "pay-bill", "prize", "lucky"}
MAX_HOPS = 4
TIMEOUT = 3.0


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    return raw


def is_public_host(host: str) -> bool:
    """SSRF guard: every address the host resolves to must be public."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return bool(infos)


class UrlAnalyzer:
    def __init__(self, network_enabled: bool = True, whois_enabled: bool = False,
                 blocklist: set[str] | None = None):
        self.network_enabled = network_enabled
        self.whois_enabled = whois_enabled
        self.blocklist = blocklist if blocklist is not None else self._load_blocklist()

    @staticmethod
    def _load_blocklist() -> set[str]:
        from ..brands import DATA
        p = DATA / "blocklist.txt"
        if not p.exists():
            return set()
        return {ln.strip().lower() for ln in p.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")}

    # ---------- static signals ----------
    def static_signals(self, url: str, claimed_brands=()) -> list[tuple[str, float, str]]:
        sig: list[tuple[str, float, str]] = []
        parsed = urlsplit(normalize_url(url))
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return [("invalid_url", 0.3, "The link could not be parsed as a valid web address.")]
        reg = registered_domain(host)
        labels = host.split(".")
        tld = labels[-1]

        if host in self.blocklist or reg in self.blocklist:
            sig.append(("blocklisted", 0.95, f"{reg} appears on a known phishing blocklist."))
        try:
            ipaddress.ip_address(host)
            sig.append(("ip_host", 0.6, "The link uses a raw IP address instead of a domain name."))
        except ValueError:
            pass
        if "xn--" in host:
            sig.append(("punycode", 0.4, "The domain uses look-alike (punycode) characters."))
        if "@" in (parsed.netloc or ""):
            sig.append(("at_sign", 0.4, "The link contains '@', which can hide the real destination."))
        if parsed.scheme == "http":
            sig.append(("no_https", 0.10, "The link does not use HTTPS."))
        if len(url) > 100:
            sig.append(("long_url", 0.10, "The link is unusually long."))
        if len(labels) >= 5:
            sig.append(("many_subdomains", 0.20, "The link has an unusually deep subdomain chain."))
        if tld in SUSPICIOUS_TLDS:
            sig.append(("suspicious_tld", 0.25, f"The '.{tld}' ending is heavily used for throwaway scam domains."))
        if reg in SHORTENERS:
            sig.append(("shortener", 0.20, "It is a shortened link that hides where it really leads."))
        kw = [k for k in KEYWORDS if k in host]
        if kw:
            sig.append(("keyword_in_host", 0.20, f"The domain contains pressure words like '{kw[0]}'."))

        # brand impersonation / lookalike
        # also match with digit-for-letter swaps undone (amaz0n -> amazon)
        host_plain = host.translate(str.maketrans("0135", "oles"))
        tokens = set(re.split(r"[^a-z0-9]+", host)) | set(re.split(r"[^a-z0-9]+", host_plain))
        reg_label = reg.split(".")[0]
        flagged = False
        for b in load_brands().values():
            if is_official(host, b):
                continue
            official_labels = {registered_domain(d).split(".")[0] for d in b.domains}
            lookalike = next((ol for ol in official_labels if len(ol) >= 5 and reg_label != ol
                              and levenshtein(deobfuscate(reg_label), ol) <= 2), None)
            if lookalike:
                sig.append(("lookalike_domain", 0.80,
                            f"{reg} imitates the {b.display} domain ('{lookalike}') with small spelling changes."))
                flagged = True
            elif any(a in tokens for a in b.single_aliases) or any(
                    len(a) >= 5 and (a in host or a in host_plain) for a in b.single_aliases):
                sig.append(("brand_impersonation", 0.70,
                            f"{reg} uses the name '{b.display}' but is not an official {b.display} domain."))
                flagged = True
            if flagged:
                break

        if claimed_brands and not flagged and reg not in SHORTENERS:
            brands = load_brands()
            if not any(is_official(host, brands[k]) for k in claimed_brands if k in brands):
                names = ", ".join(brands[k].display for k in claimed_brands if k in brands)
                sig.append(("brand_mismatch", 0.60,
                            f"The message claims to be from {names}, but the link goes to {reg}, which is not an official domain."))
        return sig

    # ---------- network (sandboxed) ----------
    def follow_redirects(self, url: str) -> tuple[list[str], str | None]:
        """Follow redirects with timeouts, no JS, no body download, no private addresses."""
        import httpx
        chain = [normalize_url(url)]
        try:
            with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                              headers={"User-Agent": "ScamShield-Scanner/0.1"}) as client:
                for _ in range(MAX_HOPS):
                    host = urlsplit(chain[-1]).hostname or ""
                    if not is_public_host(host):
                        return chain, "blocked: non-public or unresolvable host"
                    with client.stream("GET", chain[-1]) as resp:  # body is never read
                        loc = resp.headers.get("location")
                        if resp.status_code in (301, 302, 303, 307, 308) and loc:
                            chain.append(urljoin(chain[-1], loc))
                            continue
                    return chain, None
            return chain, "too many redirects"
        except Exception as exc:  # network failure must never break analysis
            return chain, f"fetch failed: {type(exc).__name__}"

    def domain_age_days(self, host: str) -> int | None:
        try:
            import whois  # python-whois, optional
            created = whois.whois(registered_domain(host)).creation_date
            if isinstance(created, list):
                created = created[0]
            if created is None:
                return None
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
        except Exception:
            return None

    # ---------- public ----------
    def analyze(self, url: str, claimed_brands=()) -> DetectorResult:
        sig = self.static_signals(url, claimed_brands)
        meta: dict = {"url": url}
        host = urlsplit(normalize_url(url)).hostname or ""
        if self.network_enabled and host:
            chain, err = self.follow_redirects(url)
            meta.update(redirect_chain=chain, network_note=err)
            if len(chain) > 1:
                final = chain[-1]
                if registered_domain(urlsplit(final).hostname or "") != registered_domain(host):
                    sig += [(f"final_{c}", w, f"After redirects: {t}")
                            for c, w, t in self.static_signals(final, claimed_brands)]
                if len(chain) > 3:
                    sig.append(("redirect_chain", 0.15, "The link bounces through several redirects."))
        if self.whois_enabled and host:
            age = self.domain_age_days(host)
            meta["domain_age_days"] = age
            if age is not None and age < 30:
                sig.append(("new_domain", 0.50, f"The domain was registered only {age} days ago."))
            elif age is not None and age < 90:
                sig.append(("young_domain", 0.25, f"The domain is only {age} days old."))
        reasons = [Reason(c, t, "url", w) for c, w, t in sig]
        scam_type = "phishing_link" if sig and noisy_or([w for _, w, _ in sig]) >= 0.5 else None
        return DetectorResult("url", noisy_or([w for _, w, _ in sig]), reasons, meta, scam_type)
