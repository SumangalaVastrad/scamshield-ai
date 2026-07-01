"""Tool definitions for ScamShield AI Agent.

All tools:
1. Enforce strict input size limits and validation.
2. Return JSON-serializable dictionaries.
3. Perform strictly offline operations (ZERO network requests).
4. Heuristically analyze URLs without fetching or connecting.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import yaml

from scamhelper.nlp import extract_signals, SHORTENER_DOMAINS
from scamhelper.okf import OKFBundle
from scamhelper.rules import URGENT_EMERGENCY_STEPS

MAX_TEXT_INPUT_LENGTH = 10000
MAX_URL_INPUT_LENGTH = 2048
MAX_QUERY_LENGTH = 500

# High-risk / unusual TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "loan", "apk", "cfd", "click",
    "cam", "cc", "icu", "vip", "gq", "ml", "cf", "ga", "tk", "fit", "rest", "surf"
}

# Bank names to detect lookalikes
BANK_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob", "canara",
    "paytm", "phonepe", "gpay", "bhim", "indiapost", "incometax", "epfo"
]

_BUNDLE_CACHE: Optional[OKFBundle] = None


def _get_bundle() -> OKFBundle:
    """Lazily load bundle instance."""
    global _BUNDLE_CACHE
    if _BUNDLE_CACHE is None:
        repo_root = Path(__file__).resolve().parent.parent
        notes_dir = repo_root / "notes"
        bundle = OKFBundle(notes_dir)
        bundle.load()
        _BUNDLE_CACHE = bundle
    return _BUNDLE_CACHE


def tool_extract_signals(text: str) -> Dict[str, Any]:
    """Extract entities, URLs, phone numbers, UPI IDs, and urgency signals."""
    if not isinstance(text, str):
        return {"error": "Input text must be a string"}
    if len(text) > MAX_TEXT_INPUT_LENGTH:
        return {"error": f"Input text exceeds maximum allowed length of {MAX_TEXT_INPUT_LENGTH} characters"}

    res = extract_signals(text)
    return res.to_dict()


def tool_check_url(url: str) -> Dict[str, Any]:
    """
    Perform purely offline heuristic inspection of a URL string.
    NEVER connects to or fetches the URL.
    Returns detected risk indicators; NEVER returns 'safe' or 'malicious'.
    """
    if not isinstance(url, str):
        return {"error": "URL must be a string"}
    if len(url) > MAX_URL_INPUT_LENGTH:
        return {"error": f"URL exceeds maximum allowed length of {MAX_URL_INPUT_LENGTH} characters"}

    clean_url = url.strip()
    if not clean_url:
        return {"error": "URL cannot be empty"}

    # Prepend scheme if missing for urlparse
    parsed_input = clean_url if "://" in clean_url else "http://" + clean_url
    try:
        parsed = urlparse(parsed_input)
    except Exception as exc:
        return {"error": f"Malformed URL: {exc}"}

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    reasons: List[str] = []

    # 1. Check scheme
    is_http = parsed.scheme.lower() == "http"
    if is_http:
        reasons.append("Uses unencrypted HTTP instead of HTTPS.")

    # 2. Check IP host
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
    if is_ip:
        reasons.append("Host is a raw numerical IP address rather than a registered domain name.")

    # 3. Check Punycode / Internationalized Domain Names
    if "xn--" in host:
        reasons.append("Domain uses Punycode (xn--), often used in lookalike homograph attacks.")

    # 4. Check Shorteners
    is_shortener = any(host == s or host.endswith("." + s) for s in SHORTENER_DOMAINS)
    if is_shortener:
        reasons.append("Uses a known URL shortening service to conceal the true destination.")

    # 5. Check TLD
    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Uses an unusual top-level domain (.{tld}) commonly seen in throwaway phishing sites.")

    # 6. Check Subdomain depth
    subdomains = host.split(".")
    if len(subdomains) > 4:
        reasons.append(f"Excessive subdomain nesting ({len(subdomains)} levels), typical of phishing subdomains.")

    # 7. Check Hyphens and digits
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        reasons.append(f"Domain contains multiple hyphens ({hyphen_count}), commonly used to mimic brand names.")

    # 8. Check Brand lookalikes
    for brand in BANK_KEYWORDS:
        if brand in host:
            # Check if it's the exact official brand domain (e.g. onlinesbi.sbi or sbi.co.in)
            # If brand is combined with other words like sbi-kyc, hdfc-update
            if "-" in host or any(w in host for w in ["kyc", "verify", "login", "secure", "update", "online"]):
                reasons.append(f"Domain name embeds brand keyword '{brand}' with suspicious modifiers.")
                break

    return {
        "url": clean_url,
        "analyzed_host": host,
        "risk_signals_detected": len(reasons) > 0,
        "risk_reasons": reasons,
        "offline_heuristic_notice": "Analysis is based strictly on offline string heuristics. The destination was not fetched or validated online."
    }


def tool_search_scam_notes(query: str) -> Dict[str, Any]:
    """Search the OKF knowledge bundle for scam notes matching query."""
    if not isinstance(query, str):
        return {"error": "Query must be a string"}
    if len(query) > MAX_QUERY_LENGTH:
        return {"error": f"Query exceeds maximum allowed length of {MAX_QUERY_LENGTH} characters"}

    bundle = _get_bundle()
    matches = bundle.search_notes(query, top_k=3)
    return {
        "query": query,
        "count": len(matches),
        "results": [m.to_dict() for m in matches]
    }


def tool_get_scam_note(scam_type: str) -> Dict[str, Any]:
    """Retrieve full text and metadata for a specific scam type note."""
    if not isinstance(scam_type, str):
        return {"error": "scam_type must be a string"}

    bundle = _get_bundle()
    note = bundle.get_note(scam_type.strip())
    if not note:
        return {"error": f"No OKF note found for scam_type: '{scam_type}'"}

    return {
        "scam_type": note.scam_type,
        "title": note.title,
        "status": note.status,
        "is_draft": note.is_draft,
        "safe_content": note.get_safe_summary(),
        "red_flags": note.red_flags,
        "sources": note.sources,
        "last_verified": note.last_verified or "Not verified (draft)",
    }


def tool_get_contacts(category: str) -> Dict[str, Any]:
    """
    Retrieve contact numbers or portal links from data/contacts.yaml only.
    If unverified, returns placeholder text and marks verified as False.
    """
    if not isinstance(category, str):
        return {"error": "Category must be a string"}

    repo_root = Path(__file__).resolve().parent.parent
    contacts_file = repo_root / "data" / "contacts.yaml"

    contacts_data = {}
    if contacts_file.exists():
        try:
            with open(contacts_file, "r", encoding="utf-8") as f:
                contacts_data = yaml.safe_load(f) or {}
        except Exception as exc:
            return {"error": f"Failed reading contacts: {exc}"}

    cat_key = category.strip().lower().replace(" ", "_")
    if cat_key in contacts_data:
        val = contacts_data[cat_key]
        is_verified = bool(val.get("verified_on"))
        return {
            "category": cat_key,
            "data": val,
            "is_verified": is_verified,
            "notice": "Official contact verified" if is_verified else "Contact details not yet verified in this build."
        }

    # Return all contacts if category not found or general
    return {
        "category": "all",
        "contacts": contacts_data,
        "notice": "Contact details not yet verified in this build."
    }


def tool_escalate_urgent(reason: str) -> Dict[str, Any]:
    """Activate the emergency urgent path and retrieve immediate action steps."""
    if not isinstance(reason, str):
        reason = "Emergency action required"

    return {
        "urgent": True,
        "banner": True,
        "reason": reason[:300],
        "emergency_steps": URGENT_EMERGENCY_STEPS,
    }


# Tool Registry mapping names to functions
TOOL_REGISTRY = {
    "extract_signals": tool_extract_signals,
    "check_url": tool_check_url,
    "search_scam_notes": tool_search_scam_notes,
    "get_scam_note": tool_get_scam_note,
    "get_contacts": tool_get_contacts,
    "escalate_urgent": tool_escalate_urgent,
}
