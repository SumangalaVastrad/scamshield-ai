"""Unit tests for scamhelper.tools module."""

import pytest
from scamhelper.tools import (
    tool_check_url,
    tool_get_contacts,
    tool_extract_signals,
    tool_search_scam_notes,
    tool_get_scam_note,
    tool_escalate_urgent,
    MAX_TEXT_INPUT_LENGTH,
    MAX_URL_INPUT_LENGTH,
)


def test_check_url_never_returns_safe():
    """Safety requirement: check_url must NEVER return 'safe' or 'malicious'."""
    samples = [
        "https://www.google.com",
        "http://bit.ly/kyc-sbi",
        "http://192.168.1.1/login",
        "http://sbi-card-verify.xyz",
    ]
    for url in samples:
        res = tool_check_url(url)
        assert "error" not in res
        # Must never pronounce a verdict of 'safe'
        res_str = str(res).lower()
        assert "'safe'" not in res_str
        assert "'malicious'" not in res_str
        assert "risk_reasons" in res
        assert "offline_heuristic_notice" in res


def test_check_url_risk_signals():
    """Detects HTTP, IP addresses, shortened links, and bank lookalikes."""
    res_short = tool_check_url("http://bit.ly/sbi-update")
    assert res_short["risk_signals_detected"] is True
    assert any("shorten" in r.lower() for r in res_short["risk_reasons"])
    assert any("http" in r.lower() for r in res_short["risk_reasons"])

    res_ip = tool_check_url("http://192.168.1.5/bank")
    assert any("numerical ip" in r.lower() for r in res_ip["risk_reasons"])

    res_lookalike = tool_check_url("https://sbi-kyc-update.xyz/login")
    assert any("sbi" in r.lower() for r in res_lookalike["risk_reasons"])
    assert any(".xyz" in r.lower() for r in res_lookalike["risk_reasons"])


def test_get_contacts_returns_placeholders_when_unverified():
    """get_contacts returns the exact placeholder text from contacts.yaml when unverified."""
    res = tool_get_contacts("national_cybercrime_helpline")
    assert "error" not in res
    assert res["is_verified"] is False
    assert "[FILL" in res["data"]["number"] or "portal" in res["data"]
    assert "not yet verified in this build" in res["notice"]


def test_tools_reject_oversized_and_malformed_input():
    """Tools must gracefully handle and reject oversized and malformed inputs."""
    # Oversized text
    huge_text = "a" * (MAX_TEXT_INPUT_LENGTH + 100)
    res_huge = tool_extract_signals(huge_text)
    assert "error" in res_huge
    assert "exceeds maximum allowed length" in res_huge["error"]

    # Malformed non-string inputs
    assert "error" in tool_extract_signals(None)
    assert "error" in tool_extract_signals(12345)

    # Oversized URL
    huge_url = "http://example.com/" + ("b" * (MAX_URL_INPUT_LENGTH + 10))
    res_url = tool_check_url(huge_url)
    assert "error" in res_url
    assert "exceeds maximum allowed length" in res_url["error"]


def test_get_scam_note_returns_draft():
    """Verify that get_scam_note respects draft status and returns safe_content."""
    res = tool_get_scam_note("fake_kyc")
    assert "error" not in res
    assert res["scam_type"] == "fake_kyc"
    assert res["is_draft"] is True
    assert "draft note, not yet verified" in res["safe_content"]


def test_escalate_urgent_tool():
    """Verify emergency tool activation."""
    res = tool_escalate_urgent("User entered PIN on fraud call")
    assert res["urgent"] is True
    assert res["banner"] is True
    assert len(res["emergency_steps"]) >= 4
