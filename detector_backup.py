import re
from urllib.parse import urlparse

HIGH_RISK_PATTERNS = {
    "Urgency / pressure": [
        r"\b(urgent|immediately|right now|act now|within \d+ minutes?|last chance)\b",
        r"\b(account|sim|card|wallet)\b.{0,35}\b(blocked|suspended|deactivated)\b",
    ],
    "Credential request": [
        r"\b(otp|one[- ]time password|password|pin|cvv|mpin|passcode)\b",
        r"\b(share|send|provide|tell|verify)\b.{0,35}\b(otp|pin|password|cvv)\b",
    ],
    "Financial request": [
        r"\b(send|transfer|pay|deposit|invest)\b.{0,45}\b(₹|\$|rs\.?|inr|\d{3,})\b",
        r"\b(refund|prize|lottery|cashback|reward|bonus)\b.{0,45}\b(upi|bank|account|fee|charge|pay)\b",
    ],
    "Impersonation": [
        r"\b(bank|police|income tax|customs|government|support|hr|recruiter)\b",
        r"\b(verify your identity|kyc|know your customer)\b",
    ],
    "Threat / consequence": [
        r"\b(fine|arrest|legal action|police case|warrant|penalty|jail)\b",
        r"\b(your account will be closed|service will stop|number will be blocked)\b",
    ],
}

FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}

def extract_urls(text):
    return re.findall(r"https?://[^\s<>()]+|www\.[^\s<>()]+", text, flags=re.I)

def url_flags(url):
    raw = url if re.match(r"^https?://", url, re.I) else "http://" + url
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    flags = []
    if p.scheme != "https":
        flags.append("Link is not using HTTPS")
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        flags.append("Link uses an IP address instead of a normal domain")
    if "@" in p.netloc:
        flags.append("Link contains an @ symbol, which can hide the real destination")
    if len(url) > 100:
        flags.append("Unusually long URL")
    suspicious_words = ["verify", "login", "secure", "refund", "kyc", "gift", "claim", "update"]
    if any(w in host for w in suspicious_words):
        flags.append("Domain contains a high-risk keyword")
    return host, flags

def analyze_message(text):
    lower = text.lower()
    score = 0
    reasons = []
    categories = []
    matched = set()

    for category, patterns in HIGH_RISK_PATTERNS.items():
        category_hit = False
        for pattern in patterns:
            if re.search(pattern, lower):
                category_hit = True
                break
        if category_hit:
            matched.add(category)
            categories.append(category)
            if category in {"Credential request", "Financial request"}:
                score += 27
            elif category in {"Impersonation", "Threat / consequence"}:
                score += 18
            else:
                score += 14

    urls = extract_urls(text)
    url_details = []
    for url in urls:
        host, flags = url_flags(url)
        url_details.append({"url": url, "host": host, "flags": flags})
        if flags:
            score += min(24, 8 + 4 * len(flags))
            reasons.extend(flags)

    # Behavioral signals
    if re.search(r"\b(click|tap|open|download|install)\b", lower) and urls:
        score += 10
        reasons.append("Message pushes you toward a link or download")
    if re.search(r"\b(secret|confidential|do not tell|don't tell|keep this private)\b", lower):
        score += 10
        reasons.append("Message asks for secrecy")
    if re.search(r"\bcongratulations\b|\byou (won|have won)\b", lower):
        score += 12
        reasons.append("Unexpected prize/reward claim")
    if text.count("!") >= 3:
        score += 4
        reasons.append("Excessive punctuation/pressure language")

    score = min(100, score)

    if score >= 70:
        verdict, level = "Likely scam", "high"
    elif score >= 40:
        verdict, level = "Suspicious", "medium"
    else:
        verdict, level = "Low risk", "low"

    # De-duplicate while preserving order
    unique_reasons = []
    for r in reasons:
        if r not in unique_reasons:
            unique_reasons.append(r)

    if categories:
        unique_reasons = categories + unique_reasons

    explanation = (
        "This message shows several common social-engineering signals."
        if level == "high"
        else "This message has some signals worth checking before you act."
        if level == "medium"
        else "No strong scam pattern was detected by the current rule-based model."
    )

    return {
        "score": score,
        "verdict": verdict,
        "level": level,
        "explanation": explanation,
        "reasons": unique_reasons[:8],
        "urls": url_details,
        "recommendations": [
            "Do not share OTPs, passwords, PINs, CVVs, or recovery codes.",
            "Do not pay or transfer money because a message creates urgency.",
            "Open the organization's official app/site yourself instead of using the message link.",
            "If it is a job/investment offer, independently verify the company and sender.",
        ],
        "model": "ScamShield v1 — explainable rule-based risk engine",
    }
