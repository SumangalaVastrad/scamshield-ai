"""NLP signal and entity extraction for ScamShield AI.

Extracts URLs, shortened links, phone numbers, UPI IDs, rupee amounts,
brand names, urgency signals, sensitive data requests, and money-already-sent triggers.
Uses regex rules as foundation, with optional spaCy enrichment if en_core_web_sm is available.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import yaml

from scamhelper.schemas import EntitySignal, ExtractionResult

# Common URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "rotf.lol",
    "ow.ly",
    "v.gd",
    "buff.ly",
    "adf.ly",
    "rebrand.ly",
}

# Known UPI handles (VPA suffixes)
KNOWN_UPI_HANDLES = {
    "okaxis",
    "okhdfcbank",
    "okicici",
    "oksbi",
    "ybl",
    "ibl",
    "axl",
    "paytm",
    "upi",
    "sbi",
    "hdfcbank",
    "icici",
    "kotak",
    "postbank",
    "barodampay",
    "apl",
    "waaxis",
    "wahdfc",
    "waicici",
    "wasbi",
    "allbank",
    "aubank",
    "axisgo",
    "bandhan",
    "canara",
    "citi",
    "dbs",
    "equitas",
    "federal",
    "indus",
    "pnb",
    "rbl",
    "sib",
    "uco",
    "unionbank",
    "yesbank",
}

# Standard email domains to exclude from UPI ID detection
EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "rediffmail.com",
    "mail.com",
    "live.com",
}

# Urgency and pressure keyword patterns
URGENCY_PATTERNS = [
    r"\bimmediat(?:ely)?\b",
    r"\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b",
    r"\baccount\s+will\s+be\s+blocked\b",
    r"\baccount\s+(?:suspended|blocked|deactivated)\b",
    r"\blast\s+warning\b",
    r"\bfinal\s+notice\b",
    r"\bsuspended\b",
    r"\burgent\b",
    r"\bverify\s+now\b",
    r"\bact\s+now\b",
    r"\btoday\s+itself\b",
    r"\bdisconnect(?:ed|ion)?\s+(?:tonight|today)\b",
    r"\bpower\s+cut\b",
    r"\bimmediate\s+action\b",
    r"\blimited\s+time\b",
    r"\bexpire(?:s|d)?\s+today\b",
    r"\btorrent\s+power\s+cut\b",
]

# Sensitive data request patterns
SENSITIVE_DATA_PATTERNS = [
    r"\botp\b",
    r"\bone[-\s]?time\s+password\b",
    r"\bpin\b",
    r"\bupi\s+pin\b",
    r"\bcvv\b",
    r"\bcrc\b",
    r"\bpassword\b",
    r"\bpasscode\b",
    r"\bcard\s+number\b",
    r"\bdebit\s+card\b",
    r"\bcredit\s+card\b",
    r"\baadhaar(?:\s+number|\s+card)?\b",
    r"\bpan(?:\s+card|\s+number)?\b",
    r"\bshare\s+your\s+upi\b",
    r"\benter\s+(?:your\s+)?(?:upi\s+)?pin\b",
    r"\benter\s+(?:your\s+)?otp\b",
    r"\bshare\s+otp\b",
    r"\bbank\s+details\b",
    r"\bnet\s*banking\s+password\b",
]

# Money already sent / urgent trigger phrases
MONEY_ALREADY_SENT_PATTERNS = [
    r"\bi\s+(?:already\s+)?paid\b",
    r"\balready\s+paid\b",
    r"\bpaid\b.*?\balready\b",
    r"\bpaid\s+(?:rs\.?|inr|₹)?\s*[\d,]+\b",
    r"\bpaid\s+via\s+upi\b",
    r"\bsent\s+money\b",
    r"\balready\s+sent\b",
    r"\btransferred\b",
    r"\balready\s+transferred\b",
    r"\bmoney\s+debited\b",
    r"\bdebited\b",
    r"\bentered\s+my\s+card\b",
    r"\bentered\s+card\s+details\b",
    r"\bshared\s+(?:my\s+)?otp\b",
    r"\bgave\s+(?:my\s+)?otp\b",
    r"\btold\s+them\s+(?:my\s+)?(?:otp|pin|cvv)\b",
    r"\bgave\s+(?:my\s+)?pin\b",
    r"\bshared\s+(?:my\s+)?pin\b",
    r"\binstalled\s+(?:the\s+)?app\b",
    r"\bgave\s+remote\s+access\b",
    r"\banydesk\b",
    r"\brustdesk\b",
    r"\bteamviewer\b",
    r"\bquicksupport\b",
    r"\bscreen\s+sharing\b",
    r"\bdigital\s+arrest\b",
    r"\bthey\s+are\s+still\s+on\s+call\b",
    r"\bthreatening\s+me\b",
    r"\barrest\s+warrant\b",
    r"\bon\s+video\s+call\b",
]

# Fallback brands if brands.yaml not found
DEFAULT_BRANDS = [
    "SBI", "State Bank of India", "HDFC", "HDFC Bank", "ICICI", "ICICI Bank",
    "Axis", "Axis Bank", "Kotak", "Kotak Mahindra", "PNB", "Punjab National Bank",
    "Canara Bank", "Bank of Baroda", "BOB", "PhonePe", "Paytm", "Google Pay",
    "GPay", "BHIM", "Amazon", "Amazon Pay", "Flipkart", "India Post", "Post Office",
    "BlueDart", "DTDC", "Delhivery", "Income Tax", "IT Department", "EPFO",
    "PF Office", "RBI", "Reserve Bank of India", "Electricity Board", "BESCOM",
    "BSES", "MSEDCL", "Torrent Power", "Indane", "Bharat Gas", "HP Gas", "TRAI",
    "DoT", "CBI", "Police", "Cyber Police", "Customs", "FedEx", "DHL"
]

_SPACY_NLP = None
_SPACY_LOAD_ATTEMPTED = False


def _get_spacy_nlp():
    """Lazily load spaCy en_core_web_sm model if available."""
    global _SPACY_NLP, _SPACY_LOAD_ATTEMPTED
    if not _SPACY_LOAD_ATTEMPTED:
        _SPACY_LOAD_ATTEMPTED = True
        try:
            import spacy
            _SPACY_NLP = spacy.load("en_core_web_sm")
        except Exception:
            _SPACY_NLP = None
    return _SPACY_NLP


def load_brands(brands_path: Optional[str] = None) -> List[str]:
    """Load brand names from YAML file or return defaults."""
    if brands_path and os.path.exists(brands_path):
        try:
            with open(brands_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "brands" in data:
                    return data["brands"]
        except Exception:
            pass

    # Try standard relative path
    repo_root = Path(__file__).resolve().parent.parent
    candidate = repo_root / "data" / "brands.yaml"
    if candidate.exists():
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "brands" in data:
                    return data["brands"]
        except Exception:
            pass

    return DEFAULT_BRANDS


def detect_language(text: str) -> str:
    """Detect language of the text: en, hi, kn, etc."""
    # Check for Kannada Unicode script range (\u0C80 - \u0CFF)
    if re.search(r"[\u0C80-\u0CFF]", text):
        return "kn"
    # Check for Devanagari (Hindi) Unicode script range (\u0900 - \u097F)
    if re.search(r"[\u0900-\u097F]", text):
        return "hi"

    try:
        from langdetect import detect
        detected = detect(text)
        return str(detected)
    except Exception:
        return "en"


def extract_signals(text: str, brands_path: Optional[str] = None) -> ExtractionResult:
    """
    Extract structured signals from user text:
    URLs, shortened URLs, phone numbers, UPI IDs, rupee amounts, brands,
    urgency phrases, sensitive data requests, and money-already-sent phrases.
    """
    signals: List[EntitySignal] = []
    brands_list = load_brands(brands_path)

    # 1. URLs
    url_pattern = re.compile(
        r"(?:https?://|www\.)[^\s<>'\"`]+",
        re.IGNORECASE
    )
    urls: List[str] = []
    shortened_urls: List[str] = []
    url_spans: List[Tuple[int, int]] = []

    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        span = (match.start(), match.start() + len(url))
        url_spans.append(span)
        urls.append(url)

        # Check if shortened domain
        domain_match = re.search(r"https?://(?:www\.)?([^/]+)", url, re.IGNORECASE)
        domain = domain_match.group(1).lower() if domain_match else ""
        if any(domain == s or domain.endswith("." + s) for s in SHORTENER_DOMAINS):
            shortened_urls.append(url)
            signals.append(EntitySignal("shortened_url", url, span))
        else:
            signals.append(EntitySignal("url", url, span))

    # Also detect domain-like shorteners without scheme (e.g., bit.ly/xyz, cutt.ly/abc)
    # only if not already within an extracted URL span
    bare_shortener_pattern = re.compile(
        r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)/[a-zA-Z0-9_\-]+",
        re.IGNORECASE
    )
    for match in bare_shortener_pattern.finditer(text):
        start, end = match.span()
        # Check if overlapping with any existing url_spans
        if any(s_start <= start and end <= s_end for s_start, s_end in url_spans):
            continue
        val = match.group(0)
        urls.append(val)
        shortened_urls.append(val)
        url_spans.append((start, end))
        signals.append(EntitySignal("shortened_url", val, (start, end)))

    # 2. Indian & Toll-Free Phone Numbers
    # Mobile 10 digit, landline STD, or toll-free (1800...)
    phone_pattern = re.compile(
        r"(?:\b1800[-\s]?\d{3}[-\s]?\d{3,4}\b|(?:\+91[\s-]?)?(?:0)?[6-9]\d{4}[\s-]?\d{5}\b|\b0\d{2,4}[-\s]?\d{6,8}\b|(?:\+1[\s-]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b)",
        re.IGNORECASE
    )
    phones: List[str] = []
    for match in phone_pattern.finditer(text):
        val = match.group(0)
        span = match.span()
        phones.append(val)
        signals.append(EntitySignal("phone", val, span))

    # 3. UPI IDs (e.g. merchant@okaxis, user@upi, name@sbi)
    upi_pattern = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,64}@([a-zA-Z0-9.\-_]{2,32})\b"
    )
    upi_ids: List[str] = []
    for match in upi_pattern.finditer(text):
        full_val = match.group(0)
        handle = match.group(1).lower()
        span = match.span()

        # Exclude regular email domains
        if handle in EMAIL_DOMAINS or (full_val.lower().endswith(".com") and handle not in KNOWN_UPI_HANDLES):
            continue

        upi_ids.append(full_val)
        is_known = handle in KNOWN_UPI_HANDLES
        signal_type = "upi_id" if is_known else "unknown_upi_id"
        signals.append(EntitySignal(signal_type, full_val, span))

    # 4. Amounts in $, ₹, Rs, INR, USD
    amount_pattern = re.compile(
        r"(?:(?:[\$₹]|rs\.?|inr|usd)\s*[\d,]+(?:\.\d{1,2})?|\b[\d,]+(?:\.\d{1,2})?\s*(?:[\$₹]|rs\.?|inr|rupees|dollars?|usd|lakhs?|crores?)\b)",
        re.IGNORECASE
    )
    amounts: List[str] = []
    for match in amount_pattern.finditer(text):
        val = match.group(0).strip()
        span = match.span()
        amounts.append(val)
        signals.append(EntitySignal("amount", val, span))

    # 4b. Card Suffixes (e.g. "card ending 1234", "a/c ending in 8821", "XX4921")
    card_suffix_pattern = re.compile(
        r"\b(?:card|a/c|account)\s+(?:ending\s+(?:in\s+|with\s+)?|xx\s*|ending:?\s*)(\d{4})\b|\bcard\s+xx(\d{4})\b|\bxx(\d{4})\b",
        re.IGNORECASE
    )
    card_suffixes: List[str] = []
    for match in card_suffix_pattern.finditer(text):
        val = match.group(0).strip()
        span = match.span()
        card_suffixes.append(val)
        signals.append(EntitySignal("card_suffix", val, span))

    # 4c. IVR / "Press 1" Prompts (e.g. "press 1", "dial 1 to speak to security")
    ivr_pattern = re.compile(
        r"\b(?:press|dial)\s+([0-9]|#|\*)(?:\s+(?:to|for)\s+[a-zA-Z\s]{1,30})?\b",
        re.IGNORECASE
    )
    ivr_options: List[str] = []
    for match in ivr_pattern.finditer(text):
        val = match.group(0).strip()
        span = match.span()
        ivr_options.append(val)
        signals.append(EntitySignal("ivr_option", val, span))

    # 5. Bank and Brand Names
    found_brands: List[str] = []
    for brand in sorted(brands_list, key=len, reverse=True):
        # Word boundary matching
        pattern = re.compile(r"\b" + re.escape(brand) + r"\b", re.IGNORECASE)
        for match in pattern.finditer(text):
            val = match.group(0)
            span = match.span()
            if brand not in found_brands:
                found_brands.append(brand)
            signals.append(EntitySignal("brand", val, span))

    # 6. Urgency Phrases
    urgency_phrases: List[str] = []
    for pat in URGENCY_PATTERNS:
        for match in re.finditer(pat, text, re.IGNORECASE):
            val = match.group(0)
            span = match.span()
            urgency_phrases.append(val)
            signals.append(EntitySignal("urgency", val, span))

    # 7. Sensitive Data Requests
    sensitive_requests: List[str] = []
    for pat in SENSITIVE_DATA_PATTERNS:
        for match in re.finditer(pat, text, re.IGNORECASE):
            val = match.group(0)
            span = match.span()
            sensitive_requests.append(val)
            signals.append(EntitySignal("sensitive_data", val, span))

    # 8. Money Already Sent / Urgent Triggers
    money_already_sent: List[str] = []
    for pat in MONEY_ALREADY_SENT_PATTERNS:
        for match in re.finditer(pat, text, re.IGNORECASE):
            val = match.group(0)
            span = match.span()
            money_already_sent.append(val)
            signals.append(EntitySignal("money_already_sent", val, span))

    # 9. Optional spaCy Enrichment
    nlp_model = _get_spacy_nlp()
    spacy_available = nlp_model is not None
    if spacy_available and nlp_model:
        try:
            doc = nlp_model(text)
            for ent in doc.ents:
                if ent.label_ in ("ORG", "MONEY", "PERSON", "DATE"):
                    signals.append(
                        EntitySignal(f"spacy_{ent.label_.lower()}", ent.text, (ent.start_char, ent.end_char))
                    )
        except Exception:
            pass

    lang = detect_language(text)

    return ExtractionResult(
        text=text,
        signals=signals,
        urls=list(dict.fromkeys(urls)),
        shortened_urls=list(dict.fromkeys(shortened_urls)),
        phone_numbers=list(dict.fromkeys(phones)),
        upi_ids=list(dict.fromkeys(upi_ids)),
        amounts=list(dict.fromkeys(amounts)),
        card_suffixes=list(dict.fromkeys(card_suffixes)),
        ivr_options=list(dict.fromkeys(ivr_options)),
        brands=list(dict.fromkeys(found_brands)),
        urgency_phrases=list(dict.fromkeys(urgency_phrases)),
        sensitive_data_requests=list(dict.fromkeys(sensitive_requests)),
        money_already_sent_phrases=list(dict.fromkeys(money_already_sent)),
        language=lang,
        spacy_available=spacy_available,
    )
