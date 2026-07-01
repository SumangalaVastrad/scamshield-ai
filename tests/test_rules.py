"""Unit tests for scamhelper.rules module."""

import pytest
from scamhelper.rules import evaluate_rules, check_urgent_trigger, is_legitimate_warning


def test_verdict_scam_high_risk():
    """Text with shortened link + sensitive data request + urgency should be SCAM."""
    text = (
        "Dear SBI Customer, your account is suspended! Update your KYC immediately "
        "within 24 hours to avoid block. Enter OTP and PIN at http://bit.ly/sbi-verify"
    )
    result = evaluate_rules(text)
    assert result.verdict == "SCAM"
    assert result.scam_type == "fake_kyc"
    assert len(result.red_flags) >= 2
    assert any("shortened" in rf.lower() for rf in result.red_flags)
    assert any("sensitive" in rf.lower() or "otp" in rf.lower() for rf in result.red_flags)


def test_verdict_likely_scam():
    """Text with suspicious link and urgency without asking for credentials."""
    text = "Your courier parcel IND9821 cannot be delivered. Click http://bit.ly/post-fee to update."
    result = evaluate_rules(text)
    assert result.verdict in ("LIKELY SCAM", "SCAM")
    assert result.scam_type == "parcel_fee"


def test_verdict_unsure():
    """Vague text with minimal indicators."""
    text = "Reminder: Your appointment with customer care executive is scheduled for tomorrow."
    result = evaluate_rules(text)
    assert result.verdict in ("UNSURE", "LOOKS LEGITIMATE")


def test_verdict_looks_legitimate():
    """Legitimate bank alert with OTP and security disclaimer should not be marked SCAM."""
    text = (
        "Dear Customer, 483921 is your OTP for purchase of Rs 1,499 at Amazon. "
        "Valid for 10 mins. Do not share this OTP with anyone, including bank staff. "
        "If not done by you, SMS BLOCK to 567676."
    )
    result = evaluate_rules(text)
    assert result.verdict == "LOOKS LEGITIMATE"
    assert result.urgent is False
    assert is_legitimate_warning(text) is True


def test_urgent_trigger_on_action():
    text = "Dear customer verify KYC. I already sent money to the caller yesterday."
    is_urgent, reasons = check_urgent_trigger(text)
    assert is_urgent is True
    assert len(reasons) > 0


def test_no_false_urgent_on_plain_legitimate():
    text = "Salary credited: Rs 45,000 to your HDFC account XX1234 on 25-Oct-2026. Avail balance: Rs 78,000."
    is_urgent, reasons = check_urgent_trigger(text)
    assert is_urgent is False
    assert len(reasons) == 0

    result = evaluate_rules(text)
    assert result.urgent is False
    assert result.urgent_banner is False
