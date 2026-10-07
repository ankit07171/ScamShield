from app.detectors import rules


def ids(text):
    return set(rules.evaluate(text).meta["rule_ids"])


def test_pin_to_receive_is_flagged():
    assert "pin_to_receive" in ids("You have received Rs 5000. Enter your UPI PIN to receive the money.")


def test_hinglish_pin_trick():
    assert "pin_to_receive" in ids("PIN daalo aur paise milenge, Rs 3000 cashback aaya hai")


def test_collect_request():
    assert "collect_request" in ids("I accidentally sent Rs 5000 to your UPI. Please accept the collect request to return it.")


def test_share_otp_flagged_but_warning_is_not():
    assert "share_otp" in ids("Please share the OTP you received to confirm your refund.")
    assert "share_otp" not in ids("Your OTP is 482913. Do not share it with anyone. - HDFC Bank")
    assert "share_otp" not in ids("Never share this OTP with anyone.")


def test_hindi_kyc_and_electricity():
    assert "kyc_urgent" in ids("आपका केवाईसी समाप्त हो गया है।")
    assert "electricity_bill" in ids("Your power will be disconnected tonight at 9:30 PM")


def test_normal_chat_has_no_hits():
    assert ids("Hey, are we still meeting for lunch tomorrow at 1?") == set()


def test_ordinary_approval_request_is_not_a_collect_scam():
    assert "collect_request" not in ids("Please approve the leave request when you get a chance.")
    assert "collect_request" in ids("Approve the collect request on your UPI app to get your refund of Rs 2,499.")
