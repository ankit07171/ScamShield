H = {"X-API-Key": "user-key"}
ADMIN = {"X-API-Key": "admin-key"}


def test_pin_to_receive_is_high_risk(client):
    r = client.post("/v1/analyze/message", json={"text": "You have received Rs 5000 cashback. Enter your UPI PIN to receive the money."}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "High risk"
    assert any("PIN" in x["text"] for x in body["reasons"])
    assert body["education"]["title"]


def test_kyc_phishing_with_fake_link(client):
    r = client.post("/v1/analyze/message", json={"text": "Dear SBI customer, your KYC has expired. Update immediately at http://sbi-kyc-update.xyz or account will be blocked."})
    assert r.json()["verdict"] == "High risk"


def test_legit_otp_message_is_safe(client):
    r = client.post("/v1/analyze/message", json={"text": "Your OTP for login is 482913. Do not share it with anyone. - HDFC Bank"})
    assert r.json()["verdict"] == "Safe"


def test_casual_message_is_safe(client):
    r = client.post("/v1/analyze/message", json={"text": "Hey, are we still meeting for lunch tomorrow at 1?"})
    assert r.json()["verdict"] == "Safe"


def test_url_endpoint(client):
    assert client.post("/v1/analyze/url", json={"url": "https://www.sbi.co.in"}).json()["verdict"] == "Safe"
    assert client.post("/v1/analyze/url", json={"url": "http://hdfc-secure-verify.top/login"}).json()["verdict"] == "High risk"


def test_upi_endpoint(client):
    assert client.post("/v1/analyze/upi", json={"upi_id": "9876543210@ybl"}).json()["verdict"] == "Safe"
    assert client.post("/v1/analyze/upi", json={"upi_id": "refund.support@ybl"}).json()["verdict"] in {"Suspicious", "High risk"}


def test_qr_upi_with_amount_warns(client):
    r = client.post("/v1/analyze/qr", json={"decoded_text": "upi://pay?pa=refund.care@ybl&pn=Refund&am=4999&tn=receive refund"})
    body = r.json()
    assert body["verdict"] in {"Suspicious", "High risk"}
    assert any(x["code"] == "qr_has_amount" for x in body["reasons"])


def test_validation_and_auth_modes(client):
    assert client.post("/v1/analyze/message", json={"text": ""}).status_code == 422
    assert client.post("/v1/analyze/qr", json={}).status_code == 422


def test_community_reports_raise_reputation(client):
    upi = "lucky.winner77@ybl"
    before = client.post("/v1/analyze/upi", json={"upi_id": upi}).json()["score"]
    ids = []
    for _ in range(4):
        # only admins/verified carry full weight; reports are moderated
        r = client.post("/v1/reports", json={"entity_type": "upi", "value": upi, "scam_type": "lottery", "region": "Maharashtra"}, headers=ADMIN)
        assert r.status_code == 201
    # moderation endpoint requires admin
    assert client.patch("/v1/reports/1", json={"status": "verified"}, headers=H).status_code == 403
    for rid in range(1, 5):
        assert client.patch(f"/v1/reports/{rid}", json={"status": "verified"}, headers=ADMIN).status_code == 200
    # cache holds the old verdict for identical input; use a fresh message form of the same ID
    msg = client.post("/v1/analyze/message", json={"text": f"Pay to {upi} to claim your gift"}).json()
    assert any(x["code"] == "community_reports" for x in msg["reasons"])
    t = client.get("/v1/reports/trends").json()
    assert t["total"] >= 4 and t["top_scam_types"][0][0] == "lottery"


def test_feedback_flow(client):
    aid = client.post("/v1/analyze/url", json={"url": "https://example.com"}).json()["analysis_id"]
    assert client.post("/v1/feedback", json={"analysis_id": aid, "user_label": "safe"}).status_code == 201
    assert client.post("/v1/feedback", json={"analysis_id": 999999, "user_label": "safe"}).status_code == 404
