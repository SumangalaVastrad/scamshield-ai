"""Unit tests for scamhelper.nlp module."""

import pytest
from scamhelper.nlp import extract_signals, detect_language, _get_spacy_nlp
from scamhelper.schemas import ExtractionResult


def test_extract_urls_and_shortened():
    text = "Visit our site at https://secure-bank.example.com or click http://bit.ly/sbi-kyc for updates."
    res = extract_signals(text)
    assert len(res.urls) == 2
    assert "https://secure-bank.example.com" in res.urls
    assert "http://bit.ly/sbi-kyc" in res.urls
    assert len(res.shortened_urls) == 1
    assert "http://bit.ly/sbi-kyc" in res.shortened_urls


def test_extract_phone_numbers():
    text = "Call customer care at +91 98765 43210 or 080-22221234 immediately."
    res = extract_signals(text)
    assert len(res.phone_numbers) >= 2
    # Verify Indian mobile detected
    assert any("98765" in p for p in res.phone_numbers)
    # Verify landline detected
    assert any("080-22221234" in p for p in res.phone_numbers)


def test_extract_upi_ids():
    text = "Send payment to merchant.store@okaxis or support@sbi. Do not email john@gmail.com."
    res = extract_signals(text)
    assert "merchant.store@okaxis" in res.upi_ids
    assert "support@sbi" in res.upi_ids
    # Normal email should NOT be counted as UPI ID
    assert "john@gmail.com" not in res.upi_ids


def test_extract_rupee_amounts():
    text = "Your account has been debited by Rs. 4,500 and fine of ₹250 or 50000 INR."
    res = extract_signals(text)
    assert len(res.amounts) >= 2
    assert any("4,500" in a or "4500" in a for a in res.amounts)
    assert any("250" in a for a in res.amounts)


def test_extract_urgency_and_sensitive_requests():
    text = "Immediate action required! Your account will be blocked within 24 hours. Enter your OTP and PIN now."
    res = extract_signals(text)
    assert len(res.urgency_phrases) >= 2
    assert any("blocked" in u.lower() or "within 24 hours" in u.lower() or "immediate" in u.lower() for u in res.urgency_phrases)
    assert len(res.sensitive_data_requests) >= 2
    assert any("otp" in s.lower() for s in res.sensitive_data_requests)
    assert any("pin" in s.lower() for s in res.sensitive_data_requests)


def test_extract_money_already_sent_phrases():
    text = "I already paid the registration fee and transferred Rs 2000. I also shared OTP and gave my PIN."
    res = extract_signals(text)
    assert len(res.money_already_sent_phrases) >= 2
    assert any("paid" in m.lower() for m in res.money_already_sent_phrases)
    assert any("transferred" in m.lower() for m in res.money_already_sent_phrases)
    assert any("shared otp" in m.lower() for m in res.money_already_sent_phrases)


def test_works_with_spacy_missing(monkeypatch):
    """Ensure extraction succeeds seamlessly even when spaCy or en_core_web_sm is missing."""
    import scamhelper.nlp as nlp_module
    monkeypatch.setattr(nlp_module, "_get_spacy_nlp", lambda: None)

    sample = "Urgent: SBI account blocked. Pay Rs 500 at http://bit.ly/sbi to unblock."
    res = nlp_module.extract_signals(sample)
    assert isinstance(res, ExtractionResult)
    assert res.spacy_available is False
    assert "SBI" in res.brands
    assert len(res.shortened_urls) == 1
    assert len(res.amounts) == 1


def test_language_detection():
    english_text = "Your electricity will be disconnected tonight."
    assert detect_language(english_text) == "en"

    hindi_text = "आपका बिजली बिल बाकी है। तुरंत भुगतान करें।"
    assert detect_language(hindi_text) == "hi"

    kannada_text = "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗಿದೆ. ತಕ್ಷಣ ನವೀಕರಿಸಿ."
    assert detect_language(kannada_text) == "kn"
