"""Rule engine: simple, auditable patterns that double as human-readable explanations."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import DetectorResult, Reason, noisy_or

_NEG = re.compile(r"(?:\bnot|\bnever|don'?t|do not|kabhi nahi|mat|कभी नहीं)\s*$", re.I)
_HI_NEG = re.compile(r"(?:\bन\b|नहीं|मत|कभी|नका)")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: re.Pattern
    reason: str
    guard_negation: bool = False  # skip matches like "do NOT share your OTP"


def R(id_, cat, w, pat, reason, neg=False):
    return Rule(id_, cat, w, re.compile(pat, re.I | re.S), reason, neg)


RULES: list[Rule] = [
    R("pin_to_receive", "collect_request", 0.90,
      r"(?:enter|share|put|type|dial|provide|use)\b[^.\n]{0,40}\b(?:upi\s*)?(?:pin|mpin)\b[^.\n]{0,60}\b(?:receive|credit|refund|get\b|claim|cashback)"
      r"|(?:receive|claim)[^.\n]{0,50}(?:enter|share|put)[^.\n]{0,30}\bpin\b"
      r"|\bpin\s+(?:dalo|daalo|enter\s+karo)[^.\n]{0,60}(?:paise|paisa|money|milenge|receive)",
      "It asks you to enter your UPI PIN to receive money. A PIN is only ever needed to SEND money, never to receive it."),
    R("collect_request", "collect_request", 0.70,
      r"(?:collect\s+request|payment\s+request)[^.\n]{0,60}(?:approve|accept|enter)"
      r"|(?:accept|approve)[^.\n]{0,30}(?:collect|payment|money|upi)\s+request[^.\n]{0,60}(?:receive|get|refund|prize|return)"
      r"|(?:accidentally|mistakenly)\s+sent[^.\n]{0,60}(?:accept|return|refund)",
      "It asks you to approve a payment 'collect' request to get or return money. Approving a collect request takes money out of your account."),
    R("share_otp", "otp_theft", 0.60,
      r"(?:share|send|tell|forward|give|provide|read out)\b[^.\n]{0,25}\b(?:otp|one[- ]time password|cvv|card pin)\b"
      r"|\botp\s+(?:batao|bata\s+do|share\s+karo|bhejo)"
      r"|(?:ओटीपी|otp)[^.\n]{0,15}(?:शेयर|बताएं|बताइए|भेजें|सांगा)",
      "It asks you to share an OTP, CVV or PIN. Banks and genuine services never ask for these.", True),
    R("kyc_urgent", "phishing_kyc", 0.45,
      r"\bkyc\b[^.\n]{0,40}(?:expire|expired|update|pending|suspend|block|verify|incomplete)"
      r"|(?:update|complete|verify)[^.\n]{0,20}\bkyc\b|केवाईसी|केवायसी",
      "It uses the classic 'KYC expired / pending' hook to push you to a link or call."),
    R("account_blocked", "phishing_kyc", 0.40,
      r"(?:account|a/c|card|upi|wallet|sim|pan)[^.\n]{0,30}(?:blocked|suspended|deactivated|frozen|freezed|closed|disconnected)"
      r"|(?:account|khata|kyc|pan)[^.\n]{0,30}(?:band|block)\s+ho\s+(?:jayega|jaega|jayegi)"
      r"|(?:खाता|खाते|कार्ड)[^.\n]{0,20}(?:बंद|ब्लॉक|निलंबित)|(?:बंद|ब्लॉक)\s+होईल",
      "It threatens that your account, card or SIM will be blocked."),
    R("urgency", "pressure", 0.20,
      r"(?:within|in)\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|\b(?:immediately|urgent(?:ly)?|asap|last chance|today only|act now|final (?:notice|warning))\b"
      r"|expires?\s+(?:today|tonight)|\b(?:abhi|turant|jaldi)\b|तुरंत|जल्द\s*से\s*जल्द",
      "It creates artificial urgency, a common pressure tactic."),
    R("lottery", "lottery", 0.55,
      r"(?:lottery|lucky draw|jackpot|you(?:'ve| have)? won|prize money|congratulations[^.\n]{0,40}won)"
      r"|(?:inaam|inam|lottery)\s+(?:jeet|lagi|mila)|लॉटरी|इनाम",
      "It claims you won a lottery or prize you never entered."),
    R("fee_to_claim", "lottery", 0.50,
      r"(?:processing|registration|release|clearance|delivery|customs)\s+(?:fee|charge|tax)[^.\n]{0,40}(?:pay|send|deposit|transfer)"
      r"|(?:pay|send|deposit)[^.\n]{0,40}(?:processing|registration|release|clearance)\s+(?:fee|charge)"
      r"|(?:processing|registration)\s+fee\s+(?:rs|₹)",
      "It asks for an upfront fee to release money, a prize or a job. Genuine prizes and jobs do not charge fees."),
    R("job_scam", "job", 0.50,
      r"(?:work from home|part[- ]time|online job|data entry|task[- ]based|like (?:and )?subscribe)[^.\n]{0,80}(?:₹|rs\.?|inr)\s?\d"
      r"|(?:earn|income)[^.\n]{0,20}(?:₹|rs\.?|inr)\s?\d[\d,]*\s*(?:per|/|a)\s*(?:day|daily|hour|week)"
      r"|work from home[^.\n]{0,60}(?:per day|daily)",
      "It promises unrealistic income for easy work-from-home or task jobs."),
    R("investment_scam", "investment", 0.55,
      r"guaranteed\s+(?:returns?|profit)|100%\s+guaranteed|double\s+your\s+(?:money|investment)"
      r"|\d{1,3}\s?%\s*(?:daily|weekly|monthly)\s*returns?|\d{1,3}\s?%\s+returns?\s+(?:every|per)\s+(?:day|week|month)"
      r"|(?:vip|premium)\s+(?:trading|stock|crypto)\s+(?:group|tips|signals)|insider\s+tips",
      "It promises guaranteed or very high investment returns."),
    R("electricity_bill", "fake_electricity_bill", 0.55,
      r"(?:electricity|power)\s+(?:bill|connection|supply)?[^.\n]{0,60}(?:disconnect|cut\b|unpaid|overdue|tonight|will be cut)"
      r"|बिजली[^.\n]{0,40}(?:कट|बंद)",
      "It threatens to cut your electricity tonight unless you act, a well-known fake-bill scam."),
    R("courier_hold", "courier", 0.35,
      r"(?:parcel|package|courier|consignment|shipment)[^.\n]{0,60}(?:held|stuck|on hold|undelivered|returned|incomplete address|customs|redeliver|reschedule|could not be delivered)",
      "It claims a parcel is stuck and needs action or a small payment."),
    R("govt_threat", "govt_impersonation", 0.60,
      r"\b(?:income\s*tax|cbi|enforcement directorate|police|cyber\s*cell|trai|customs|narcotics|rbi|court)\b[^.\n]{0,60}(?:notice|arrest|warrant|case|fine|penalty|illegal)"
      r"|digital\s+arrest",
      "It impersonates a government agency and threatens arrest, a case or a fine."),
    R("relative_money", "relative_impersonation", 0.50,
      r"(?:this is my new number|lost my phone|phone (?:is )?(?:broken|broke|damaged))[^.\n]{0,100}(?:send|transfer|urgent|need|pay|money)"
      r"|(?:mom|mum|dad|papa|beta|bhai|bro)\b[^.\n]{0,60}(?:need|send)[^.\n]{0,40}(?:money|₹|rs\.?\s?\d)",
      "It looks like a 'family member on a new number' request for urgent money."),
    R("apk_install", "malware_apk", 0.60,
      r"\b[\w.-]+\.apk\b|install\s+(?:this\s+)?app\s+(?:to|for)[^.\n]{0,30}(?:kyc|update|verify|claim)",
      "It asks you to install an APK/app from outside the official store, a common way to steal banking access."),
    R("remote_access", "remote_access", 0.60,
      r"\b(?:anydesk|teamviewer|quicksupport|rustdesk)\b",
      "It asks you to install a remote-access app, which gives the caller control of your phone."),
    R("refund_claim", "phishing_link", 0.40,
      r"(?:refund|cashback|reward\s*points?)[^.\n]{0,50}(?:click|link|claim|expir|redeem|enter)"
      r"|(?:click|tap|open)[^.\n]{0,30}(?:claim|redeem)[^.\n]{0,30}(?:refund|cashback|reward)",
      "It dangles a refund, cashback or reward points behind a link."),
]


def evaluate(text: str) -> DetectorResult:
    hits: list[tuple[Rule, float]] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            span = m.group(0)
            if rule.guard_negation:
                before = text[max(0, m.start() - 20): m.start()]
                if _NEG.search(before) or _HI_NEG.search(span):
                    continue
            hits.append((rule, rule.weight))
            break
    reasons = [Reason(r.id, r.reason, "rules", w) for r, w in hits]
    scam_type = None
    specific = [(w, r.category) for r, w in hits if r.category not in {"pressure", "phishing_link"}]
    if specific:
        scam_type = max(specific)[1]
    elif hits:
        scam_type = max((w, r.category) for r, w in hits)[1]
    return DetectorResult("rules", noisy_or([w for _, w in hits]), reasons,
                          {"rule_ids": [r.id for r, _ in hits]}, scam_type)
