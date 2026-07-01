"""Command-Line Interface (CLI) for ScamShield AI / Scam and Fraud Helper.

Usage:
    python scripts/cli.py "Dear customer, your SBI account is blocked. Update at http://bit.ly/sbi"
    python scripts/cli.py "Electricity bill unpaid. Call 9876543210" --urgent
    python scripts/cli.py "Message text" --json
"""

import sys
import json
import argparse
from pathlib import Path

# Add project root to sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scamhelper.agent import ScamShieldAgent
from scamhelper.schemas import AnalysisResult


def main():
    parser = argparse.ArgumentParser(
        description="ScamShield AI CLI: Check suspicious SMS, WhatsApp, emails, or call descriptions for fraud."
    )
    parser.add_argument("message", type=str, help="The suspicious message text or call description.")
    parser.add_argument(
        "--urgent",
        action="store_true",
        help="Flag indicating that you already sent money, shared an OTP, or installed an app.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw structured JSON analysis result.",
    )

    args = parser.parse_args()

    agent = ScamShieldAgent()
    result: AnalysisResult = agent.analyze(args.message, user_ticked_urgent=args.urgent)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    # User-friendly console display
    print("=" * 60)
    print(" ScamShield AI - Scam & Fraud Guidance")
    print("=" * 60)

    if result.urgent_banner:
        print("\n[!] EMERGENCY ALERT: ACT NOW. DO THESE FIRST:")
        for i, step in enumerate(result.urgent_steps, 1):
            print(f"  {i}. {step}")
        print("-" * 60)

    print(f"\nVerdict:     {result.verdict} (Uncertainty: {result.uncertainty})")
    print(f"Scam Type:   {result.note_title or 'Unknown Pattern'}")
    if result.note_status:
        print(f"Note Status: {result.note_status} (verified sources: {len(result.sources)})")
    print(f"Engine:      {'Agentic LLM with Tools' if result.is_llm_based else 'Deterministic Rule Engine'}")

    if result.red_flags:
        print("\nRed Flags Observed:")
        for rf in result.red_flags:
            print(f"  * {rf}")

    print("\nWhat To Do Now:")
    for i, step in enumerate(result.steps, 1):
        print(f"  {i}. {step}")

    if result.trace:
        print("\nExecution Trace:")
        for step in result.trace:
            print(f"  - [{step['tool']}] {step['result_summary']}")

    print("\n" + "-" * 60)
    print(f"Disclaimer: {result.disclaimer}")
    print("Notice: Contact details not yet verified in this build.")
    print("=" * 60)


if __name__ == "__main__":
    main()
