from app.detectors.url_analyzer import UrlAnalyzer, is_public_host

A = UrlAnalyzer(network_enabled=False, blocklist=set())


def codes(url, brands=()):
    return {r.code for r in A.analyze(url, brands).reasons}


def test_official_domain_is_clean():
    r = A.analyze("https://www.sbi.co.in/web/personal-banking")
    assert r.score == 0 and not r.reasons


def test_brand_name_on_wrong_domain():
    assert "brand_impersonation" in codes("http://sbi-kyc-update.xyz/login")


def test_lookalike_and_homoglyph():
    assert "lookalike_domain" in codes("https://hdfcbnk.com")
    assert "lookalike_domain" in codes("https://amaz0n-india.com") or "brand_impersonation" in codes("https://amaz0n-india.com")


def test_message_claims_bank_but_link_differs():
    assert "brand_mismatch" in codes("https://secure-login-portal.com/x", ("sbi",))


def test_shortener_and_ip():
    assert "shortener" in codes("https://bit.ly/abc123")
    assert "ip_host" in codes("http://192.168.0.1/pay")


def test_blocklist():
    a = UrlAnalyzer(network_enabled=False, blocklist={"evil-pay.top"})
    assert a.analyze("http://evil-pay.top/x").score >= 0.9


def test_ssrf_guard_rejects_loopback():
    assert not is_public_host("127.0.0.1")
    assert not is_public_host("localhost")
    assert not is_public_host("169.254.169.254")
