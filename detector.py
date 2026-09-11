import re
import joblib
from urllib.parse import urlparse


# =====================================================
# LOAD ML MODEL
# =====================================================

ml_model = joblib.load("scam_model.pkl")


# =====================================================
# HIGH RISK PATTERNS
# =====================================================

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


# =====================================================
# URL EXTRACTION
# =====================================================

def extract_urls(text):

    return re.findall(
        r"https?://[^\s<>()]+|www\.[^\s<>()]+",
        text,
        flags=re.I
    )


def url_flags(url):

    raw = (
        url
        if re.match(r"^https?://", url, re.I)
        else "http://" + url
    )

    p = urlparse(raw)

    host = (p.hostname or "").lower()

    flags = []

    if p.scheme != "https":
        flags.append(
            "Link is not using HTTPS"
        )

    if re.match(
        r"^\d{1,3}(?:\.\d{1,3}){3}$",
        host
    ):

        flags.append(
            "Link uses an IP address instead of a normal domain"
        )

    if "@" in p.netloc:

        flags.append(
            "Link contains an @ symbol, which can hide the real destination"
        )

    if len(url) > 100:

        flags.append(
            "Unusually long URL"
        )

    suspicious_words = [
        "verify",
        "login",
        "secure",
        "refund",
        "kyc",
        "gift",
        "claim",
        "update"
    ]

    if any(
        word in host
        for word in suspicious_words
    ):

        flags.append(
            "Domain contains a high-risk keyword"
        )

    return host, flags


# =====================================================
# CATEGORY DETECTION
# =====================================================

def detect_scam_category(
    lower,
    has_job_signal,
    has_payment_signal,
    has_prize,
    has_investment,
    has_refund
):

    # ---------------------------------------------
    # Credential / phishing signals
    # ---------------------------------------------

    credential_words = [
        "otp",
        "one time password",
        "password",
        "pin",
        "cvv",
        "mpin",
        "passcode",
        "login",
        "verify your account",
        "verify your identity"
    ]

    has_credential_signal = any(
        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )
        for word in credential_words
    )


    # ---------------------------------------------
    # Job scam
    # ---------------------------------------------

    if has_job_signal and has_payment_signal:

        return "Job Scam"


    # ---------------------------------------------
    # Prize / reward scam
    # ---------------------------------------------

    if has_prize and has_payment_signal:

        return "Prize / Reward Scam"


    # ---------------------------------------------
    # Investment scam
    # ---------------------------------------------

    if has_investment and has_payment_signal:

        return "Investment Scam"


    # ---------------------------------------------
    # Refund scam
    # ---------------------------------------------

    if has_refund and (
        has_payment_signal
        or has_credential_signal
    ):

        return "Refund Scam"


    # ---------------------------------------------
    # Credential phishing
    # ---------------------------------------------

    if has_credential_signal:

        return "Credential Phishing"


    # ---------------------------------------------
    # Financial scam
    # ---------------------------------------------

    if has_payment_signal:

        return "Financial Scam"


    # ---------------------------------------------
    # General scam
    # ---------------------------------------------

    return "General Scam"


# =====================================================
# MAIN MESSAGE ANALYZER
# =====================================================

def analyze_message(text):

    lower = text.lower()

    rule_score = 0

    reasons = []

    categories = []


    # =================================================
    # 1. BASIC RULE-BASED DETECTION
    # =================================================

    for category, patterns in HIGH_RISK_PATTERNS.items():

        category_hit = False

        for pattern in patterns:

            if re.search(pattern, lower):

                category_hit = True

                break


        if category_hit:

            categories.append(category)


            if category in {
                "Credential request",
                "Financial request"
            }:

                rule_score += 27


            elif category in {
                "Impersonation",
                "Threat / consequence"
            }:

                rule_score += 18


            else:

                rule_score += 14


    # =================================================
    # 2. URL ANALYSIS
    # =================================================

    urls = extract_urls(text)

    url_details = []


    for url in urls:

        host, flags = url_flags(url)

        url_details.append({

            "url": url,

            "host": host,

            "flags": flags

        })


        if flags:

            rule_score += min(
                24,
                8 + 4 * len(flags)
            )

            reasons.extend(flags)


    # =================================================
    # 3. BEHAVIORAL SIGNALS
    # =================================================

    if re.search(
        r"\b(click|tap|open|download|install)\b",
        lower
    ) and urls:

        rule_score += 10

        reasons.append(
            "Message pushes you toward a link or download"
        )


    if re.search(
        r"\b(secret|confidential|do not tell|don't tell|keep this private)\b",
        lower
    ):

        rule_score += 10

        reasons.append(
            "Message asks for secrecy"
        )


    # Fixed prize detection:
    # uses proper word matching so "won" doesn't
    # accidentally match unrelated words.

    if (
        re.search(
            r"\bcongratulations\b",
            lower
        )
        or
        re.search(
            r"\byou (won|have won)\b",
            lower
        )
    ):

        rule_score += 12

        reasons.append(
            "Unexpected prize/reward claim"
        )


    if text.count("!") >= 3:

        rule_score += 4

        reasons.append(
            "Excessive punctuation/pressure language"
        )


    # =================================================
    # 4. JOB SCAM DETECTION
    # =================================================

    job_words = [

        "job",

        "work from home",

        "work-from-home",

        "part time",

        "part-time",

        "employment",

        "vacancy",

        "hiring",

        "selected",

        "recruitment",

        "recruiter",

        "salary"

    ]


    payment_words = [

        "registration fee",

        "registration fees",

        "joining fee",

        "joining fees",

        "security deposit",

        "deposit",

        "processing fee",

        "processing fees",

        "pay",

        "payment",

        "fee",

        "charge",

        "rs",

        "inr"

    ]


    has_job_signal = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in job_words

    )


    has_payment_signal = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in payment_words

    )


    # ₹ doesn't work well with word boundaries,
    # so check it separately.

    if "₹" in lower:

        has_payment_signal = True


    if (
        has_job_signal
        and has_payment_signal
    ):

        rule_score += 30

        reasons.append(
            "Job opportunity combined with an upfront payment request"
        )


        if "Financial request" not in categories:

            categories.append(
                "Financial request"
            )


    # =================================================
    # 5. PRIZE / REWARD + PAYMENT
    # =================================================

    prize_words = [

        "won",

        "winner",

        "prize",

        "reward",

        "cashback",

        "lottery",

        "bonus",

        "congratulations"

    ]


    fee_words = [

        "fee",

        "processing",

        "charge",

        "pay",

        "payment",

        "deposit",

        "rs",

        "inr"

    ]


    has_prize = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in prize_words

    )


    has_fee = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in fee_words

    )


    if "₹" in lower:

        has_fee = True


    if (
        has_prize
        and has_fee
    ):

        rule_score += 25

        reasons.append(
            "Prize/reward claim combined with a payment request"
        )


    # =================================================
    # 6. INVESTMENT SCAM
    # =================================================

    investment_words = [

        "investment",

        "invest",

        "trading",

        "crypto",

        "bitcoin",

        "profit",

        "returns",

        "guaranteed return",

        "double your money"

    ]


    has_investment = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in investment_words

    )


    if (
        has_investment
        and has_payment_signal
    ):

        rule_score += 25

        reasons.append(
            "Investment opportunity combined with a money request"
        )


    # =================================================
    # 7. REFUND SCAM
    # =================================================

    refund_words = [

        "refund",

        "cashback",

        "money back",

        "reimbursement"

    ]


    has_refund = any(

        re.search(
            r"\b" + re.escape(word) + r"\b",
            lower
        )

        for word in refund_words

    )


    if (
        has_refund
        and (
            has_payment_signal
            or
            "Credential request" in categories
        )
    ):

        rule_score += 22

        reasons.append(
            "Refund-related message asks for payment or sensitive information"
        )


    # =================================================
    # 8. SCAM CATEGORY
    # =================================================

    scam_category = detect_scam_category(

        lower,

        has_job_signal,

        has_payment_signal,

        has_prize,

        has_investment,

        has_refund

    )


    # =================================================
    # 9. STRONG COMBINATIONS
    # =================================================

    if (
        "Credential request" in categories
        and
        "Urgency / pressure" in categories
    ):

        rule_score += 12

        reasons.append(
            "Urgency combined with a request for sensitive credentials"
        )


    if (
        "Financial request" in categories
        and
        "Urgency / pressure" in categories
    ):

        rule_score += 10

        reasons.append(
            "Urgency combined with a financial request"
        )


    if (
        "Credential request" in categories
        and
        "Impersonation" in categories
    ):

        rule_score += 10

        reasons.append(
            "Possible impersonation combined with a credential request"
        )


    if urls and (
        "Urgency / pressure" in categories
        or
        "Credential request" in categories
        or
        "Financial request" in categories
    ):

        rule_score += 8

        reasons.append(
            "Suspicious message contains a potentially risky link"
        )


    # =================================================
    # 10. LIMIT RULE SCORE
    # =================================================

    rule_score = min(
        100,
        rule_score
    )


    # =================================================
    # 11. MACHINE LEARNING MODEL
    # =================================================

    ml_probability = ml_model.predict_proba(
        [text]
    )[0][1]


    ml_score = round(
        ml_probability * 100,
        2
    )


    # =================================================
    # 12. HYBRID RISK SCORE
    # =================================================

    final_score = round(

        (rule_score * 0.50)
        +
        (ml_score * 0.50)

    )


    # =================================================
    # 13. HIGH-CONFIDENCE SIGNAL
    # =================================================

    strong_scam_signal = False


    if (
        has_job_signal
        and
        has_payment_signal
    ):

        strong_scam_signal = True


    if (
        has_prize
        and
        has_fee
    ):

        strong_scam_signal = True


    if (
        has_investment
        and
        has_payment_signal
    ):

        strong_scam_signal = True


    if (
        "Credential request" in categories
        and
        "Urgency / pressure" in categories
    ):

        strong_scam_signal = True


    if strong_scam_signal:

        final_score += 10


    final_score = min(
        100,
        final_score
    )


    # =================================================
    # 14. FINAL VERDICT
    # =================================================

    if final_score >= 70:

        verdict = "Likely scam"

        level = "high"

        explanation = (
            "This message shows multiple scam and "
            "social-engineering signals."
        )


    elif final_score >= 40:

        verdict = "Suspicious"

        level = "medium"

        explanation = (
            "This message contains some signals "
            "that should be verified before taking action."
        )


    else:

        verdict = "Low risk"

        level = "low"

        explanation = (
            "No strong scam pattern was detected "
            "by the current detection system."
        )


    # =================================================
    # 15. LOW-RISK CATEGORY FIX
    # =================================================

    if final_score < 40:

        scam_category = "No major scam detected"


    # =================================================
    # 16. EXPLANATIONS
    # =================================================

    reasons.insert(
        0,
        "ML model scam probability: "
        + str(ml_score)
        + "%"
    )


    if categories:

        reasons = categories + reasons


    # Remove duplicate reasons

    unique_reasons = []


    for reason in reasons:

        if reason not in unique_reasons:

            unique_reasons.append(
                reason
            )


    # =================================================
    # 17. FINAL RESPONSE
    # =================================================

    return {

        "score": final_score,

        "verdict": verdict,

        "level": level,

        "scam_category": scam_category,

        "explanation": explanation,

        "reasons": unique_reasons[:10],

        "urls": url_details,

        "ml_score": ml_score,

        # Compatibility with existing frontend
        "ml_probability": ml_score,

        "rule_score": rule_score,

        "recommendations": [

            "Do not share OTPs, passwords, PINs, CVVs, or recovery codes.",

            "Do not pay or transfer money because a message creates urgency.",

            "Open the organization's official app or website yourself instead of using the message link.",

            "Never pay an upfront registration or security fee for an unexpected job offer.",

            "If it is a job or investment offer, independently verify the company and sender."

        ],

        "model": (
            "ScamShield v4 — "
            "Hybrid ML + Explainable Multi-Signal Detection"
        )

    }