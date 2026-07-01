"""Streamlit Web Application for ScamShield AI / Scam and Fraud Helper.

Provides:
- Instant scam analysis and classification
- Immediate emergency banner and actionable recovery steps for urgent scenarios
- Extracted entity breakdown (URLs, UPI IDs, Phone numbers, Amounts)
- OKF knowledge base note grounding and draft status transparency
- Step-by-step decision trace logging
- Copyable formal cybercrime/bank complaint draft generator
- Optional OCR screenshot ingestion (if Tesseract is installed)
- Interactive session follow-up Q&A
- Evaluation dashboard and Knowledge Base Explorer
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import streamlit as st

# Add project root to sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scamhelper.agent import ScamShieldAgent
from scamhelper.schemas import AnalysisResult
from scamhelper.nlp import extract_signals
from scamhelper.tools import _get_bundle
from scamhelper.llm import LLMWrapper

# Page configuration
st.set_page_config(
    page_title="ScamShield AI | Scam and Fraud Helper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .urgent-banner {
        background-color: #fee2e2;
        border: 2px solid #ef4444;
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 24px;
        color: #991b1b;
    }
    .urgent-banner h3 {
        color: #b91c1c;
        margin-top: 0;
    }
    .verdict-card {
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        color: #ffffff;
    }
    .verdict-scam {
        background: linear-gradient(135deg, #dc2626, #991b1b);
    }
    .verdict-likely-scam {
        background: linear-gradient(135deg, #ea580c, #c2410c);
    }
    .verdict-unsure {
        background: linear-gradient(135deg, #ca8a04, #a16207);
    }
    .verdict-legit {
        background: linear-gradient(135deg, #16a34a, #15803d);
    }
    .red-flag-item {
        background-color: #fff1f2;
        border-left: 4px solid #f43f5e;
        padding: 8px 12px;
        margin-bottom: 8px;
        border-radius: 4px;
    }
    .step-item {
        background-color: #f0fdf4;
        border-left: 4px solid #22c55e;
        padding: 8px 12px;
        margin-bottom: 8px;
        border-radius: 4px;
    }
    .footer-note {
        font-size: 0.85rem;
        color: #64748b;
        margin-top: 40px;
        border-top: 1px solid #e2e8f0;
        padding-top: 15px;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = []
if "last_result" not in st.session_state:
    st.session_state["last_result"] = None
if "is_urgent_session" not in st.session_state:
    st.session_state["is_urgent_session"] = False


# Sidebar Controls
with st.sidebar:
    st.title("🛡️ ScamShield AI")
    st.caption("OKF-Grounded Assistant for Scam Guidance")

    nav_mode = st.radio("Navigation", ["Message Checker", "Evaluation Dashboard", "Knowledge Base Explorer"])

    st.markdown("---")
    st.markdown("### Engine Selection")
    engine_choice = st.radio(
        "Analysis Engine:",
        ["Rule-Based (offline)", "LLM Agent (Gemini)"],
        help="Rule-Based works offline. LLM Agent requires a GEMINI_API_KEY set in .env"
    )
    use_llm = (engine_choice == "LLM Agent (Gemini)")

    st.markdown("---")
    st.markdown("### System Status")
    agent_inst = ScamShieldAgent()
    if use_llm:
        if agent_inst.llm.is_available():
            st.success(f"LLM Engine: Active ({agent_inst.llm.model_name})")
        else:
            st.warning("LLM Agent selected but GEMINI_API_KEY not found. Will fall back to Rule-Based.")
    else:
        st.info("Engine: Deterministic Rule-Based (Offline)")

    bundle = _get_bundle()
    st.caption(f"Knowledge Bundle: {len(bundle.notes)} notes loaded")

    st.markdown("---")
    st.markdown("### Quick Examples")
    sample_options = {
        "Custom Message": "",
        "Fake KYC Suspended SMS": "Dear Customer, your SBI account KYC is suspended. Your account will be blocked today within 24 hours. Click here to verify: http://bit.ly/sbi-kyc",
        "Fake India Post Parcel Fee": "India Post: Your package IND983421 cannot be delivered due to incomplete address. Please pay redelivery fee of Rs. 25 at: http://cutt.ly/indiapost-fee",
        "UPI Collect Request Trick": "Sir, I have sent you Rs 5,000 for your OLX sofa. Open Google Pay, click approve and enter your UPI PIN to claim money.",
        "Legitimate Bank Alert": "Rs. 1,500 debited from HDFC Bank A/C XX4921 on 26-Oct-2026. Avail Bal: Rs 42,300. If not done by you, SMS BLOCK to 5676712. Do not share OTP.",
        "Emergency: Already Sent Money": "Received a call saying my electricity will be cut. I panicked and I already sent money of Rs 3,500 via UPI. What do I do now?",
    }
    selected_sample = st.selectbox("Load Sample:", list(sample_options.keys()))


# Tab 1: Message Checker
if nav_mode == "Message Checker":
    st.title("Scam and Fraud Helper")
    st.markdown(
        "Paste a suspicious message or describe a call. The assistant analyzes red flags, "
        "checks verified OKF knowledge notes, and guides your immediate safe actions."
    )

    # Urgent Checkbox
    user_ticked_urgent = st.checkbox(
        "🚨 **I already sent money, shared an OTP/PIN/card, or installed an app.**",
        value=st.session_state["is_urgent_session"],
        help="Check this immediately if money was debited or credentials were shared for prioritized emergency recovery steps."
    )

    input_mode = st.radio("Input Type:", ["Text Message / Call Description", "Upload Screenshot (OCR)"], horizontal=True)

    user_text = ""
    if input_mode == "Text Message / Call Description":
        default_val = sample_options[selected_sample] if selected_sample != "Custom Message" else ""
        user_text = st.text_area(
            "Paste the message or describe the conversation:",
            value=default_val,
            height=120,
            placeholder="e.g. Your electricity will be disconnected tonight. Call officer at 9876543210..."
        )
    else:
        uploaded_file = st.file_uploader("Upload screenshot (PNG, JPG, JPEG):", type=["png", "jpg", "jpeg"])
        if uploaded_file is not None:
            # Check for pytesseract
            try:
                import pytesseract
                from PIL import Image
                img = Image.open(uploaded_file)
                st.image(img, caption="Uploaded Screenshot", width=350)
                with st.spinner("Extracting text via OCR..."):
                    ocr_text = pytesseract.image_to_string(img)
                    user_text = st.text_area("OCR Extracted Text (you may edit):", value=ocr_text, height=120)
            except Exception as e:
                st.warning(
                    f"OCR unavailable: {e}. To enable OCR, install the Tesseract system binary. "
                    "You can still paste the screenshot text manually above."
                )
                user_text = st.text_area("Paste text manually:", height=100)

    col1, col2 = st.columns([1, 5])
    with col1:
        check_button = st.button("🔍 Check Message", type="primary", use_container_width=True)

    if check_button and user_text.strip():
        with st.spinner("Analyzing message against security signals and knowledge base..."):
            agent = ScamShieldAgent()
            # Respect engine choice: force rule-based when offline mode selected
            if not use_llm:
                from scamhelper.rules import evaluate_rules
                result = evaluate_rules(user_text, user_ticked_urgent=user_ticked_urgent)
                result.engine_used = "Rule-Based (offline)"
            else:
                result = agent.analyze(user_text, user_ticked_urgent=user_ticked_urgent)
                result.engine_used = (
                    f"LLM Agent ({agent.llm.model_name})" if result.is_llm_based else "Rule-Based (offline, LLM unavailable)"
                )
            st.session_state["last_result"] = result
            if result.urgent:
                st.session_state["is_urgent_session"] = True

    # Render Results
    result = st.session_state["last_result"]
    if result:
        st.markdown("---")

        # URGENT BANNER (Flow B)
        if result.urgent_banner or st.session_state["is_urgent_session"]:
            st.markdown("""
            <div class="urgent-banner">
                <h3>🚨 ACT NOW. DO THESE FIRST. (EMERGENCY RESPONSE)</h3>
                <p>Every minute matters. Follow these immediate containment steps right now:</p>
            </div>
            """, unsafe_allow_html=True)

            for i, step in enumerate(result.urgent_steps, 1):
                st.error(f"**Step {i}:** {step}")

            # Complaint draft generator button
            with st.expander("📝 Generate Official Complaint Text (Copy & Paste)"):
                st.markdown("Copy this pre-formatted statement to report to your bank and cybercrime portal:")
                date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                nlp_meta = extract_signals(user_text)
                amounts_found = ", ".join(nlp_meta.amounts) if nlp_meta.amounts else "[Amount in Rupees]"
                phones_found = ", ".join(nlp_meta.phone_numbers) if nlp_meta.phone_numbers else "[Fraudster Phone/Contact]"
                upis_found = ", ".join(nlp_meta.upi_ids) if nlp_meta.upi_ids else "[Fraudster UPI ID]"

                complaint_template = f"""SUBMISSION TO CYBERCRIME HELPLINE / BANK GRIEVANCE CELL

Incident Date & Time: {date_str}
Incident Category: {result.note_title or 'Financial Online Fraud'}
Amount Defrauded / Disputed: {amounts_found}
Suspect Identifier (Phone): {phones_found}
Suspect Identifier (UPI ID / Link): {upis_found}

Incident Summary:
I received a fraudulent communication stating: "{user_text[:250]}...". Believing the representation to be genuine, I took action which led to unauthorized financial transactions/data disclosure. 

Requested Action:
1. Immediately freeze beneficiary accounts/wallets linked to the suspect UPI/Account.
2. Initiate inter-bank recall/reversal of disputed funds.
3. Block compromised cards and register this formal dispute.

Attachments: Screenshots of SMS/Chat and Transaction Reference (UTR) receipts.
"""
                st.text_area("Complaint Draft:", value=complaint_template, height=220)

            st.markdown("---")

        # Standard Verdict Display
        # Map internal strings -> display strings -> CSS class
        VERDICT_DISPLAY_MAP = {
            "SCAM": ("🚨 LIKELY SCAM", "verdict-scam"),
            "LIKELY SCAM": ("⚠️ LIKELY SCAM", "verdict-likely-scam"),
            "UNSURE": ("🤔 SUSPICIOUS / NOT SURE", "verdict-unsure"),
            "LOOKS LEGITIMATE": ("✅ LIKELY SAFE", "verdict-legit"),
            # New canonical strings (LLM path)
            "Likely scam": ("🚨 LIKELY SCAM", "verdict-scam"),
            "Suspicious": ("⚠️ SUSPICIOUS", "verdict-likely-scam"),
            "Not sure": ("🤔 NOT SURE", "verdict-unsure"),
            "Likely safe": ("✅ LIKELY SAFE", "verdict-legit"),
        }
        display_verdict, verdict_class = VERDICT_DISPLAY_MAP.get(
            result.verdict, (result.verdict, "verdict-unsure")
        )

        st.markdown(f"""
        <div class="verdict-card {verdict_class}">
            <h2 style="margin:0; color:white;">Verdict: {display_verdict}</h2>
            <p style="margin:5px 0 0 0; opacity: 0.9; font-size: 0.95rem;">
                Confidence / Uncertainty: <strong>{result.uncertainty.upper()}</strong> | 
                Engine: <strong>{getattr(result, 'engine_used', 'Rule-Based (offline)')}</strong> |
                <em>Guidance, not a guarantee.</em>
            </p>
        </div>
        """, unsafe_allow_html=True)

        col_main, col_side = st.columns([2, 1])

        with col_main:
            # Scam type & note info
            if result.note_title:
                note_status_badge = f"*{result.note_status} note*" if result.note_status else ""
                st.markdown(f"#### Matched Pattern: **{result.note_title}** {note_status_badge}")
                if result.note_status == "draft":
                    st.caption("ℹ️ Note is currently in draft status (not yet verified with official gazette). Safe generic advice is provided.")

            # Red flags
            st.markdown("### 🚩 Red Flags Identified")
            if result.red_flags:
                for rf in result.red_flags:
                    st.error(rf)
            else:
                st.info("No overt scam red flags detected in the message text.")

            # Safe next steps
            st.markdown("### 📋 What To Do Now")
            for i, step in enumerate(result.steps, 1):
                st.success(f"**{i}.** {step}")

        with col_side:
            st.markdown("### 🔍 Detected Signals")
            nlp_signals = extract_signals(user_text)

            if nlp_signals.shortened_urls or nlp_signals.urls:
                st.markdown("**Web Links:**")
                for u in nlp_signals.urls:
                    st.code(u)
            if nlp_signals.phone_numbers:
                st.markdown("**Phone Numbers:**")
                for p in nlp_signals.phone_numbers:
                    st.code(p)
            if nlp_signals.upi_ids:
                st.markdown("**UPI IDs:**")
                for upi in nlp_signals.upi_ids:
                    st.code(upi)
            if nlp_signals.amounts:
                st.markdown("**Amounts:**")
                for amt in nlp_signals.amounts:
                    st.code(amt)
            if getattr(nlp_signals, "card_suffixes", []):
                st.markdown("**Card Suffixes:**")
                for cs in nlp_signals.card_suffixes:
                    st.code(cs)
            if getattr(nlp_signals, "ivr_options", []):
                st.markdown("**IVR / Press Options:**")
                for ivr in nlp_signals.ivr_options:
                    st.code(ivr)
            if nlp_signals.brands:
                st.markdown("**Brands Mentioned:**")
                st.write(", ".join(nlp_signals.brands))

            st.markdown(f"**Detected Language:** `{nlp_signals.language}`")

        # Expandable Decision Trace
        with st.expander("🔬 How this was decided (Execution Trace & Safety Logs)"):
            st.markdown(f"**Analysis Mode:** {'Agentic LLM with Tools' if result.is_llm_based else 'Deterministic Rule Engine'}")
            st.markdown(f"**Engine Used:** `{getattr(result, 'engine_used', 'Rule-Based (offline)')}`")
            st.markdown(f"**Rule Engine Score:** `{result.rule_score}`")
            if result.sources:
                st.markdown("**Knowledge Sources Cited:**")
                for s in result.sources:
                    st.markdown(f"- {s.get('name')} (Status: {s.get('status')})")

            if result.trace:
                st.markdown("**Agent Tool Execution Trace:**")
                for t in result.trace:
                    st.markdown(f"- **`{t['tool']}`** (time: {t.get('timestamp', 0)}s)")
                    if t.get("args"):
                        st.caption(f"Args: `{t['args']}`")
                    st.code(t.get("result_summary", ""), language="text")
            else:
                st.caption("Direct evaluation by rule-based scoring engine without sub-agent tool calls.")

        # Follow-up Q&A
        st.markdown("---")
        st.markdown("### 💬 Ask a Follow-up Question")
        followup_q = st.text_input(
            "Have a question about this message? (e.g., 'Is it safe to click the link?', 'What if I already called them?')",
            key="followup_input"
        )
        if st.button("Ask Follow-up"):
            if followup_q.strip():
                with st.spinner("Consulting guidelines..."):
                    # Check urgent cues in follow-up
                    from scamhelper.rules import check_urgent_trigger
                    is_urg_fu, _ = check_urgent_trigger(followup_q)
                    if is_urg_fu:
                        st.session_state["is_urgent_session"] = True
                        st.error("🚨 Detected urgent action in your follow-up! Act immediately using the emergency steps above.")

                    agent = ScamShieldAgent()
                    if agent.llm.is_available():
                        followup_prompt = (
                            f"Context: The user previously analyzed this message:\n'{user_text}'\n"
                            f"Previous Verdict: {result.verdict}, Scam Type: {result.note_title}\n\n"
                            f"User's Follow-up Question: '{followup_q}'\n\n"
                            f"Provide clear, safe, non-legal advice in simple language. Never say a suspicious link is safe."
                        )
                        answer = agent.llm.generate_text(followup_prompt)
                    else:
                        answer = (
                            "In general, if you have doubts, do not interact with the sender. "
                            "Contact your bank directly via the phone number printed on your debit card."
                        )

                    st.markdown(f"**Answer:** {answer}")


# Tab 2: Evaluation Dashboard
elif nav_mode == "Evaluation Dashboard":
    st.title("📊 Evaluation Dashboard")
    st.markdown(
        "Empirical performance comparison across **System A** (Rules only), "
        "**System B** (Plain LLM), and **System C** (Full ScamShield Agent)."
    )

    eval_results_file = repo_root / "eval" / "results" / "summary.json"
    if eval_results_file.exists():
        import json
        with open(eval_results_file, "r", encoding="utf-8") as f:
            eval_data = json.load(f)

        st.markdown("### Benchmark Performance Comparison")
        metrics_table = eval_data.get("metrics_table", [])
        if metrics_table:
            st.dataframe(metrics_table, use_container_width=True)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Evaluation Test Messages", eval_data.get("total_messages", 100))
        with col2:
            st.metric("Agent Urgent Recall", f"{eval_data.get('system_c_urgent_recall', 100):.1f}%")
        with col3:
            st.metric("Invented Contacts (Hallucinations)", eval_data.get("invented_contacts", 0))

        st.markdown("### Error Analysis & Observations")
        for obs in eval_data.get("observations", []):
            st.markdown(f"- {obs}")
    else:
        st.info("Evaluation results have not been generated yet. Run `python eval/run_eval.py` to produce benchmark results.")


# Tab 3: Knowledge Base Explorer
elif nav_mode == "Knowledge Base Explorer":
    st.title("📚 Open Knowledge Format (OKF) Knowledge Base")
    st.markdown("Browse all verified and draft scam pattern notes in the bundle.")

    bundle = _get_bundle()
    scam_notes = [n for n in bundle.notes.values() if n.type == "scam_type"]

    st.markdown(f"**Total Registered Scam Types:** {len(scam_notes)}")

    selected_note_title = st.selectbox(
        "Select a Scam Type Note to view:",
        [n.title for n in scam_notes]
    )

    selected_note = next((n for n in scam_notes if n.title == selected_note_title), None)
    if selected_note:
        st.markdown(f"## {selected_note.title}")
        st.markdown(f"**Status:** `{selected_note.status}` | **Scam ID:** `{selected_note.scam_type}`")

        if selected_note.aliases:
            st.markdown(f"**Common Aliases:** {', '.join(selected_note.aliases)}")

        st.markdown("---")
        st.markdown(selected_note.body)

        if selected_note.sources:
            st.markdown("### Sources")
            for src in selected_note.sources:
                st.markdown(f"- [{src.get('name')}]({src.get('url')}) (Accessed: {src.get('accessed')})")


# Global Footer
st.markdown("""
<div class="footer-note">
    <strong>Disclaimer:</strong> This is guidance, not a guarantee. Verify with your bank and the official cybercrime portal before acting.<br>
    <strong>Verification Notice:</strong> Contact details not yet verified in this build (using official placeholders).
</div>
""", unsafe_allow_html=True)
