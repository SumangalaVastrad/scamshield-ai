"""Unit tests specifically covering the urgent path behavior."""

import pytest
from scamhelper.rules import evaluate_rules, check_urgent_trigger, URGENT_EMERGENCY_STEPS


def test_urgent_path_triggered_by_text():
    """Text containing 'I already sent money' activates urgent banner and emergency steps."""
    text_urgent = (
        "Got an SMS saying electricity bill unpaid. I called the number and I already sent money "
        "via UPI of Rs 2500."
    )
    res_urgent = evaluate_rules(text_urgent)

    assert res_urgent.urgent is True
    assert res_urgent.urgent_banner is True
    assert len(res_urgent.urgent_steps) > 0
    assert any("freeze" in step.lower() or "bank" in step.lower() for step in res_urgent.urgent_steps)
    assert any("1930" in step or "cybercrime" in step.lower() for step in res_urgent.urgent_steps)


def test_urgent_path_not_triggered_without_action():
    """Identical scam text without the urgent action phrases does not activate the urgent banner."""
    text_normal = (
        "Got an SMS saying electricity bill unpaid. Call the number immediately to pay Rs 2500."
    )
    res_normal = evaluate_rules(text_normal)

    assert res_normal.urgent is False
    assert res_normal.urgent_banner is False
    assert len(res_normal.urgent_steps) == 0


def test_urgent_path_user_checkbox():
    """Even if text has no keywords, ticking user_ticked_urgent triggers the urgent path."""
    text = "Is this text from HDFC genuine?"
    res = evaluate_rules(text, user_ticked_urgent=True)

    assert res.urgent is True
    assert res.urgent_banner is True
    assert len(res_urgent_steps := res.urgent_steps) > 0
