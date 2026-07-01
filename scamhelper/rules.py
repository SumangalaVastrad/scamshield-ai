"""Rule-based scam and fraud classifier for ScamShield AI.

Operates deterministically without requiring an LLM or network connection.
Scores extracted signals, evaluates urgent triggers, matches scam types,
and generates structured next steps and red flag explanations.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from scamhelper.schemas import ExtractionResult, AnalysisResult, URLAnalysis
from scamhelper.nlp import extract_signals

# ==============================================================================
# SCORING CONSTANTS & THRESHOLDS
# ==============================================================================
SCORE_SHORTENED_URL = 3        # High indicator of obfuscated phishing destination
SCORE_URL_PRESENT = 2          # General link in unsolicited message
SCORE_SENSITIVE_DATA_REQ = 4   # Asks user for OTP, PIN, CVV, password, card info
SCORE_URGENCY_PHRASE = 2       # High pressure / fear tactics
SCORE_SCAM_BAIT_PHRASE = 3     # Typical scam hooks (work from home, QR scan to get money, lottery win, loan without cibil)
SCORE_UNKNOWN_UPI = 3          # Unrecognized or odd UPI handle
SCORE_KNOWN_UPI_REQUEST = 2    # Request involving UPI
SCORE_OFFICIAL_IMPERSONATION = 2 # Claims to be bank, police, courier, electricity board
SCORE_URGENT_ACTION = 5        # User already paid, shared OTP/PIN, or under active threat
SCORE_LEGIT_DISCLAIMER_BONUS = -3 # Legitimate "Do not share OTP" or official bank advisory

# Verdict thresholds
THRESHOLD_SCAM = 6             # Score >= 6 -> SCAM
THRESHOLD_LIKELY_SCAM = 3      # Score 3 to 5 -> LIKELY SCAM
THRESHOLD_UNSURE = 1           # Score 1 to 2 -> UNSURE
                               # Score <= 0 -> LOOKS LEGITIMATE

# ==============================================================================
# URGENT TRIGGER KEYWORDS AND PATTERNS
# ==============================================================================
URGENT_TRIGGERS: List[str] = [
    "already paid",
    "i paid",
    "paid already",
    "paid via upi",
    "paid rs",
    "sent money",
    "transferred",
    "money debited",
    "debited",
    "shared otp",
    "gave otp",
    "told them my pin",
    "told them my cvv",
    "gave my pin",
    "shared pin",
    "entered my card",
    "entered card details",
    "clicked the link and entered",
    "installed app",
    "gave remote access",
    "anydesk",
    "rustdesk",
    "teamviewer",
    "quicksupport",
    "screen sharing",
    "digital arrest",
    "they are still on call",
    "threatening me",
    "arrest warrant",
    "on video call",
]

# Patterns that indicate typical fraud hooks or bait promises
SCAM_BAIT_PATTERNS = [
    r"part[-\s]?time\s+job",
    r"work\s+from\s+home",
    r"earn\s+rs\.?\s*\d+",
    r"daily\s+from\s+home",
    r"like\s+youtube\s+videos",
    r"guaranteed\s+.*?(?:profit|return)",
    r"double\s+your\s+(?:money|crypto|capital)",
    r"lucky\s+draw",
    r"kbc\s+lucky",
    r"won\s+rs\.?\s*\d+",
    r"scan\s+(?:this\s+)?qr\s+code",
    r"approve\s+request\s+and\s+enter\s+pin",
    r"send\s+request\s+to\s+.*?to\s+receive",
    r"no\s+cibil\s+required",
    r"approved\s+in\s+\d+\s+minutes",
    r"telegram\s+(?:group|task|channel|@)",
    r"whatsapp\s+pink",
    r"digital\s+arrest",
    r"non[-\s]?bailable\s+warrant",
    r"narcotics",
    r"parcel\s+.*?held\s+at\s+customs",
    r"clear\s+handling\s+charge",
]

# Patterns that indicate a legitimate security warning rather than a scam request
LEGIT_SECURITY_WARNING_PATTERNS = [
    r"do\s+not\s+share\s+(?:this\s+)?(?:otp|pin|password|cvv)",
    r"never\s+share\s+(?:your\s+)?(?:otp|pin|password|cvv)",
    r"not\s+shared\s+with\s+anyone",
    r"bank\s+never\s+asks\s+for\s+(?:otp|pin|cvv)",
    r"if\s+not\s+requested\s+by\s+you[,\s]+(?:call|sms|block)",
]

# Standard emergency steps for urgent path
URGENT_EMERGENCY_STEPS: List[str] = [
    "Call your bank's emergency helpline immediately (use the number printed on the back of your card) to freeze your bank account, net banking, and block debit/credit cards.",
    "Call the National Cybercrime Helpline at 1930 immediately or lodge an incident on the national cybercrime portal.",
    "If you installed any app (like AnyDesk or an APK), disconnect your phone from the internet (turn on Airplane mode) and uninstall the app immediately.",
    "Do not transfer any more money, regardless of what the caller says or threatens. Real government agencies never arrest anyone over video call.",
    "Preserve all evidence: take screenshots of messages, transaction reference numbers (UTR), recipient UPI IDs, and call logs.",
]


def check_urgent_trigger(
    text: str,
    user_ticked_urgent: bool = False,
    nlp_result: Optional[ExtractionResult] = None
) -> Tuple[bool, List[str]]:
    """
    Check if the user's situation demands the emergency urgent path.
    Returns (is_urgent, matching_reasons).
    """
    reasons: List[str] = []

    if user_ticked_urgent:
        reasons.append("User indicated they already sent money or shared sensitive credentials.")

    lower_text = text.lower()
    for trigger in URGENT_TRIGGERS:
        if trigger in lower_text:
            reasons.append(f"Detected urgent phrase: '{trigger}'")

    if nlp_result and nlp_result.money_already_sent_phrases:
        for phrase in nlp_result.money_already_sent_phrases:
            reason_str = f"Action taken indicator: '{phrase}'"
            if reason_str not in reasons:
                reasons.append(reason_str)

    # Check for combination: "I shared" / "I gave" + OTP/PIN
    combo_pattern = re.compile(r"\b(?:i\s+)?(?:shared|gave|entered|sent)\b.*?\b(?:otp|pin|cvv|password|card)\b", re.IGNORECASE)
    if combo_pattern.search(text):
        combo_str = "User described sharing OTP, PIN, or card credentials"
        if combo_str not in reasons:
            reasons.append(combo_str)

    is_urgent = len(reasons) > 0 or user_ticked_urgent
    return is_urgent, reasons


def is_legitimate_warning(text: str) -> bool:
    """Check if the text is a legitimate bank OTP / alert with security disclaimers."""
    lower_text = text.lower()
    for pat in LEGIT_SECURITY_WARNING_PATTERNS:
        if re.search(pat, lower_text):
            return True
    return False


def match_scam_type_by_rules(text: str, nlp_res: ExtractionResult) -> Tuple[Optional[str], Optional[str]]:
    """
    Match text to one of the 12 known scam types using keyword heuristics.
    Returns (scam_type_id, scam_title).
    """
    lower = text.lower()

    # 1. Parcel / Courier (before digital arrest customs check)
    if any(k in lower for k in [
        "parcel", "package", "courier", "redelivery fee", "india post", "address incomplete",
        "customs fee", "handling charge", "customs clearance", "shipment", "delivery failed",
        "dtdc", "bluedart", "delhivery", "ಪಾರ್ಸೆಲ್", "ವಿಳಾಸ"
    ]):
        return "parcel_fee", "Fake parcel or customs fee"

    # 2. Impersonation & Digital Arrest
    if any(k in lower for k in [
        "digital arrest", "cbi", "narcotics", "mumbai police", "cyber police", "skype call",
        "video call with", "arrest warrant", "trai", "dot warning", "money laundering",
        "customs office mumbai", "special cell", "tax evasion", "income tax department notice"
    ]):
        return "impersonation_digital_arrest", "Impersonation and digital arrest"

    # 3. Malicious APK & Remote Access
    if any(k in lower for k in [
        "anydesk", "rustdesk", "quicksupport", "teamviewer", ".apk", "screen share",
        "accessibility permission", "whatsapp pink", "remote tool"
    ]):
        return "remote_access_apk", "Malicious APK and remote access"

    # 4. Utility Disconnection
    if any(k in lower for k in [
        "electricity", "power will be disconnected", "power cut", "gas disconnection",
        "electricity officer", "bescom", "bses", "png gas", "water board", "बिजली", "उपभोक्ता"
    ]):
        return "utility_disconnection", "Utility disconnection notice"

    # 5. Fake KYC Update
    if any(k in lower for k in [
        "kyc", "pan card", "pan link", "aadhaar", "account will be blocked", "account is blocked",
        "account is suspended", "netbanking is suspended", "re-kyc", "debit card is deactivated",
        "केवाईसी", "पैन कार्ड", "ಖಾತೆ", "ಕೆವೈಸಿ"
    ]):
        return "fake_kyc", "Fake KYC update"

    # 6. UPI Collect & Refund Tricks
    if any(k in lower for k in [
        "collect request", "scan qr", "enter pin to receive", "enter your upi pin to claim",
        "refund trick", "olx payment", "cashback", "reverse double deduction", "claim-reward",
        "approve request and enter pin", "paytm refund", "test my upi id", "send rs 1", "test upi"
    ]):
        return "upi_refund", "UPI refund or collect request"

    # 7. Fake Job & Task Fraud
    if any(k in lower for k in [
        "work from home", "youtube like", "part time job", "task bonus", "daily income",
        "telegram task", "hotel review task", "maps rating", "data entry work", "influencer task",
        "घर बैठे"
    ]):
        return "fake_job", "Fake job offer and task scam"

    # 8. Investment & Crypto Scam
    if any(k in lower for k in [
        "trading group", "stock tip", "crypto profit", "guaranteed return", "vip trading",
        "institutional account", "pre-ipo", "arbitrage bot", "forex trading", "शेयर मार्केट"
    ]):
        return "investment_scam", "Investment and stock tip group scam"

    # 9. Fake Loan App
    if any(k in lower for k in [
        "instant loan", "loan app", "7 day loan", "cibil", "fast cash loan", "quick cash loan",
        "personal loan of rs", "ಸಾಲ"
    ]):
        return "fake_loan_app", "Fake loan app harassment"

    # 10. Lottery & Prize Scams
    if any(k in lower for k in [
        "lottery", "kbc", "25 lakh", "lucky draw", "prize winner", "won cash", "won a new",
        "lucky winner", "बधाई हो", "करोड़पति"
    ]):
        return "lottery_prize", "Lottery and prize scam"

    # 11. Fraud alert callback and IVR scam ("press 1 to speak to security")
    if any(k in lower for k in [
        "press 1", "press 2", "press 0", "speak to security", "fraud department",
        "fraud prevention", "stay on the line", "card ending", "unauthorized charge",
        "fraud alert", "speak to our agent", "dial 1 to", "press # to", "our security team"
    ]):
        return "fraud_callback", "Fraud alert callback and IVR scam"

    # 12. Fake Customer Care
    if any(k in lower for k in [
        "customer care", "helpline number", "support number", "google search support",
        "refund customer care", "refund helpline", "support desk"
    ]):
        return "fake_customer_care", "Fake customer care number"

    # 12. OTP & Credential Theft
    if nlp_res.sensitive_data_requests and not is_legitimate_warning(text):
        return "otp_theft", "OTP, PIN, and CVV theft"

    return None, None


def evaluate_rules(
    text: str,
    user_ticked_urgent: bool = False,
    nlp_res: Optional[ExtractionResult] = None,
    brands_path: Optional[str] = None
) -> AnalysisResult:
    """
    Evaluate message text using rule-based scoring and logic.
    Returns AnalysisResult with verdict, red flags, steps, and urgent status.
    """
    if nlp_res is None:
        nlp_res = extract_signals(text, brands_path=brands_path)

    score = 0
    red_flags: List[str] = []
    steps: List[str] = []

    is_urgent, urgent_reasons = check_urgent_trigger(
        text, user_ticked_urgent=user_ticked_urgent, nlp_result=nlp_res
    )

    legit_warning = is_legitimate_warning(text)

    # Urgent action bonus (if user already paid or breached).
    # NOTE: We add to the score only — never to red_flags.
    # The urgent checkbox is about response mode, not about scam-type classification.
    if is_urgent and not legit_warning:
        score += SCORE_URGENT_ACTION

    # 1. Evaluate URLs
    if nlp_res.shortened_urls:
        score += SCORE_SHORTENED_URL
        red_flags.append(f"Contains shortened or masked web link ({', '.join(nlp_res.shortened_urls)}). Fraudsters frequently use URL shorteners to hide dangerous destinations.")
    elif nlp_res.urls:
        score += SCORE_URL_PRESENT
        red_flags.append(f"Contains unverified web link ({', '.join(nlp_res.urls)}). Legitimate institutions rarely send direct links for sensitive account actions.")

    # 2. Evaluate sensitive data requests
    if nlp_res.sensitive_data_requests:
        if legit_warning and not nlp_res.urls and not nlp_res.shortened_urls:
            # Genuine security advisory ("Do not share your OTP with anyone")
            score += SCORE_LEGIT_DISCLAIMER_BONUS
        else:
            score += SCORE_SENSITIVE_DATA_REQ
            red_flags.append(f"Requests sensitive authentication credentials ({', '.join(nlp_res.sensitive_data_requests)}). Genuine banks and organizations will NEVER ask for your OTP, PIN, or CVV.")

    # 3. Evaluate urgency phrases
    if nlp_res.urgency_phrases:
        score += SCORE_URGENCY_PHRASE
        red_flags.append(f"Uses high-pressure or artificial urgency tactics: '{', '.join(nlp_res.urgency_phrases)}' designed to cause panic.")

    # 4. Evaluate UPI and Brands
    for signal in nlp_res.signals:
        if signal.type == "unknown_upi_id":
            score += SCORE_UNKNOWN_UPI
            red_flags.append(f"Mentions suspicious UPI address ({signal.value}).")
            break

    # 4b. Evaluate Scam Bait Hooks
    lower_text = text.lower()
    for bait_pat in SCAM_BAIT_PATTERNS:
        match = re.search(bait_pat, lower_text)
        if match:
            score += SCORE_SCAM_BAIT_PHRASE
            red_flags.append(f"Uses deceptive bait tactic: '{match.group(0)}'.")
            break

    if nlp_res.brands and (nlp_res.urls or nlp_res.sensitive_data_requests or nlp_res.urgency_phrases):
        score += SCORE_OFFICIAL_IMPERSONATION
        red_flags.append(f"Impersonates recognized institution or brand: {', '.join(nlp_res.brands)}.")

    # 5. Determine Verdict
    if score >= THRESHOLD_SCAM:
        verdict = "SCAM"
        uncertainty = "low"
    elif score >= THRESHOLD_LIKELY_SCAM:
        verdict = "LIKELY SCAM"
        uncertainty = "medium"
    elif score >= THRESHOLD_UNSURE:
        verdict = "UNSURE"
        uncertainty = "high"
    else:
        verdict = "LOOKS LEGITIMATE"
        uncertainty = "low"

    # Match scam type
    scam_type, scam_title = match_scam_type_by_rules(text, nlp_res)

    # Standard safe next steps based on verdict
    if verdict in ("SCAM", "LIKELY SCAM"):
        steps = [
            "Do not click any link, call any phone number, or reply to this message.",
            "Never share your OTP, UPI PIN, ATM PIN, or card CVV with anyone under any pretext.",
            "Verify your account status independently by opening your official bank app or dialing the number printed on your physical card.",
            "Block and report the sender's number or account on your messaging app.",
            "Report unsolicited phishing SMS to your telecom provider via Chakshu portal.",
        ]
    elif verdict == "UNSURE":
        steps = [
            "Exercise caution. Do not click links or share personal information until verified.",
            "Contact the official organization directly through their known official portal or app (not using contact info inside this message).",
            "If any money is demanded or an OTP is requested, do not proceed.",
        ]
    else:  # LOOKS LEGITIMATE
        steps = [
            "This message appears consistent with legitimate informational alerts.",
            "Always follow the safety advice in the message: never share OTP or PIN with anyone, even bank staff.",
            "If you did not initiate this transaction or account action, contact your bank immediately using the verified number on your debit card.",
        ]

    # Note status
    note_status = "draft" if scam_type else None

    # Sources placeholder
    sources = []
    if scam_title:
        sources.append({
            "name": f"Knowledge base note for {scam_title}",
            "status": note_status or "draft",
            "last_verified": "Not yet verified (draft)"
        })

    return AnalysisResult(
        verdict=verdict,
        scam_type=scam_type,
        red_flags=red_flags,
        steps=steps,
        urgent=is_urgent,
        urgent_banner=is_urgent,
        urgent_steps=URGENT_EMERGENCY_STEPS if is_urgent else [],
        uncertainty=uncertainty,
        note_title=scam_title,
        note_status=note_status,
        sources=sources,
        signals=[s.to_dict() for s in nlp_res.signals],
        trace=[],
        is_llm_based=False,
        rule_score=score,
    )
