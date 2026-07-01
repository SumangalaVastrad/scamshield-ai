"""
PDF Generator for ScamShield AI Technical Dossier and Presentation Slides.
Uses ReportLab to produce a publication-grade, professionally formatted PDF.
"""

import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

# Theme Palette
PRIMARY = colors.HexColor("#1E3A8A")     # Deep Blue
SECONDARY = colors.HexColor("#0D9488")   # Teal
DARK = colors.HexColor("#0F172A")        # Slate 900
TEXT_MUTED = colors.HexColor("#475569")  # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")    # Slate 50
BORDER_COL = colors.HexColor("#E2E8F0")  # Slate 200
ACCENT_RED = colors.HexColor("#DC2626")  # Red 600
ACCENT_GREEN = colors.HexColor("#16A34A")# Green 600


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)

        # Do not print header/footer on page 1 (cover)
        if self._pageNumber > 1:
            # Header
            self.drawString(54, letter[1] - 36, "ScamShield AI — Technical Dossier & Empirical Benchmark")
            self.setStrokeColor(BORDER_COL)
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

            # Footer
            self.line(54, 45, letter[0] - 54, 45)
            self.drawString(54, 32, "Confidential — Evaluated on Google Gemini (gemini-3.1-flash-lite) & OKF 1.0.0")
            page_text = f"Page {self._pageNumber} of {total_pages}"
            self.drawRightString(letter[0] - 54, 32, page_text)

        self.restoreState()


def build_pdf(output_paths):
    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=PRIMARY,
        spaceAfter=10,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=SECONDARY,
        spaceAfter=20,
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=DARK,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=DARK,
        spaceAfter=6,
    )
    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=DARK,
        leftIndent=14,
        spaceAfter=3,
    )
    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=DARK,
        backColor=LIGHT_BG,
        borderColor=BORDER_COL,
        borderWidth=0.5,
        borderPadding=4,
        spaceAfter=6,
    )
    callout_style = ParagraphStyle(
        "Callout_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12.5,
        textColor=PRIMARY,
        backColor=colors.HexColor("#EFF6FF"),
        borderColor=colors.HexColor("#BFDBFE"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=8,
    )
    urgent_callout = ParagraphStyle(
        "UrgentCallout",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#991B1B"),
        backColor=colors.HexColor("#FEF2F2"),
        borderColor=colors.HexColor("#FECACA"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=8,
    )
    tbl_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=DARK,
    )
    tbl_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=DARK,
    )
    tbl_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
    )

    story = []

    # =========================================================================
    # COVER / HEADER SECTION
    # =========================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("ScamShield AI", title_style))
    story.append(
        Paragraph(
            "An OKF-Grounded Agentic Scam & Fraud Defense System with Bounded LLM Reasoning and Offline Heuristics",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=PRIMARY, spaceAfter=14))

    # Metadata Box
    meta_data = [
        [
            Paragraph("<b>Status:</b> Complete & Evaluated", tbl_cell),
            Paragraph("<b>Model Evaluated:</b> Gemini 3.1 Flash Lite", tbl_cell),
            Paragraph("<b>Automated Tests:</b> 42 / 42 Passed (100%)", tbl_cell),
        ],
        [
            Paragraph("<b>Test Benchmark:</b> 130 Synthetic Messages (60 Tune / 70 Test)", tbl_cell),
            Paragraph("<b>Knowledge Standard:</b> Google OKF 1.0.0 (13 Notes)", tbl_cell),
            Paragraph("<b>Date:</b> October 2026", tbl_cell),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[2.3 * inch, 2.3 * inch, 2.4 * inch])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 1: THE PROBLEM & OFFICIAL GOVERNMENT DATA
    # =========================================================================
    story.append(Paragraph("1. The Real-World Problem & Official Fraud Data", h1_style))
    story.append(
        Paragraph(
            "Digital payments in India (UPI, Netbanking, IMPS) handle over 14 billion transactions monthly. "
            "However, digital financial fraud has surged rapidly. Fraudsters deploy deceptive SMS alerts, WhatsApp forwards, "
            "phishing links, fake customer service disguises, and high-coercion 'digital arrest' impersonation calls.",
            body_style,
        )
    )

    story.append(
        Paragraph(
            "<b>Official Government Loss Statistics (Ministry of Home Affairs / I4C):</b><br/>"
            "According to the Ministry of Home Affairs in a written reply to Lok Sabha (Unstarred Question No. 195 answered on 03.12.2024):<br/>"
            "<i>\"As per data reported on the Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS), "
            "a total amount of ₹22,845.73 crore has been reported as lost in cyber financial frauds during the calendar year 2024 "
            "(up to October 31, 2024).\"</i><br/>"
            "(Sources: Lok Sabha Q&A Portal at <u>sansad.in</u>, <u>cybercrime.gov.in</u>, and <u>pib.gov.in</u>).<br/>"
            "In Q1 2024 alone, I4C recorded over 7.4 lakh complaints totaling ₹1,750 crore lost in just four months.",
            callout_style,
        )
    )

    story.append(
        Paragraph(
            "<b>The 'Golden Hour' Containment Dilemma:</b> In active banking scams, victims typically have an ultra-narrow "
            "window (under 2 hours) to freeze bank accounts and stop beneficiary withdrawals via 1930 before fraudsters cash out via crypto or mule networks. "
            "Standard chatbots provide lengthy explanations but fail to trigger rapid emergency containment.",
            body_style,
        )
    )

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 2: ARCHITECTURE & COMPONENT MAP (EXPLICIT FILE NAMES)
    # =========================================================================
    story.append(Paragraph("2. Dual-Engine Architecture & Component Map", h1_style))
    story.append(
        Paragraph(
            "ScamShield AI couples a deterministic, zero-network rule engine with a bounded agentic LLM loop. "
            "Below is the exact component breakdown with concrete file paths:",
            body_style,
        )
    )

    arch_data = [
        [
            Paragraph("Component", tbl_header),
            Paragraph("File Path", tbl_header),
            Paragraph("Core Function & Security Boundaries", tbl_header),
        ],
        [
            Paragraph("<b>Streamlit Web App</b>", tbl_cell_bold),
            Paragraph("<code>app/streamlit_app.py</code>", tbl_cell),
            Paragraph("Interactive user interface with color-coded verdict cards, emergency banner, execution trace, and screenshot OCR.", tbl_cell),
        ],
        [
            Paragraph("<b>Agent Controller</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/agent.py</code>", tbl_cell),
            Paragraph("Bounded loop (max 5 tool calls), prompt injection defense with <code>&lt;message&gt;</code> delimiters, and PII redaction.", tbl_cell),
        ],
        [
            Paragraph("<b>Rule Engine & Urgent Gate</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/rules.py</code>", tbl_cell),
            Paragraph("Deterministic scoring engine, fast-path triage (0.14s latency), and sensitive disclosure trigger gate.", tbl_cell),
        ],
        [
            Paragraph("<b>NLP Entity Extractor</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/nlp.py</code>", tbl_cell),
            Paragraph("Regex and spaCy parsing for Indian phone formats (+91), UPI VPAs, masked card identifiers, amounts, and URLs.", tbl_cell),
        ],
        [
            Paragraph("<b>OKF Knowledge Loader</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/okf.py</code>", tbl_cell),
            Paragraph("Validates frontmatter against Google Open Knowledge Format 1.0.0 specification and manages note indexing.", tbl_cell),
        ],
        [
            Paragraph("<b>Tool Registry & Heuristics</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/tools.py</code>", tbl_cell),
            Paragraph("Offline heuristic inspection (zero live URL fetching), brand matching, and verified emergency contact lookups.", tbl_cell),
        ],
        [
            Paragraph("<b>LLM Client & Backoff</b>", tbl_cell_bold),
            Paragraph("<code>scamhelper/llm.py</code>", tbl_cell),
            Paragraph("Unified client for Google Gemini API with dynamic model discovery, exponential backoff, and dual-latency tracking.", tbl_cell),
        ],
        [
            Paragraph("<b>Evaluation Runner</b>", tbl_cell_bold),
            Paragraph("<code>eval/run_eval.py</code>", tbl_cell),
            Paragraph("Evaluates 4 systems across held-out dataset, enforces zero mock/silent fallback, and records raw audit logs.", tbl_cell),
        ],
        [
            Paragraph("<b>Evaluation Dataset</b>", tbl_cell_bold),
            Paragraph("<code>eval/messages.csv</code>", tbl_cell),
            Paragraph("130 labeled synthetic messages (60 tuning rows, 70 held-out test rows) with sanitized contact placeholders.", tbl_cell),
        ],
        [
            Paragraph("<b>OKF Knowledge Notes</b>", tbl_cell_bold),
            Paragraph("<code>notes/scam-types/*.md</code>", tbl_cell),
            Paragraph("13 comprehensive fraud notes with YAML frontmatter referencing official RBI, SEBI, NPCI, and PIB advisories.", tbl_cell),
        ],
    ]
    arch_table = Table(arch_data, colWidths=[1.8 * inch, 1.8 * inch, 3.4 * inch])
    arch_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ])
    )
    story.append(arch_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 3: THE 13 OKF GROUNDED SCAM TYPOLOGIES
    # =========================================================================
    story.append(Paragraph("3. The 13 OKF Grounded Scam Typologies", h1_style))
    story.append(
        Paragraph(
            "Every scam pattern is organized according to Google's Open Knowledge Format (OKF 1.0.0). "
            "All 13 notes currently carry <b>status: draft</b> referencing official advisories, ensuring unverified drafts "
            "are not misleadingly cited as official legal gazettes:",
            body_style,
        )
    )

    notes_list = [
        "<b>1. Fake Bank KYC:</b> Threats of netbanking suspension requiring APK download or phishing link. (Ref: RBI)",
        "<b>2. OTP & CVV Theft:</b> Social engineering calls to extract authentication tokens. (Ref: RBI Common Person Guide)",
        "<b>3. UPI Refund & Collect Trick:</b> Tricking users to enter UPI PIN to 'receive' money. (Ref: NPCI Circular)",
        "<b>4. Fake Parcel / Delivery Fee:</b> Requiring ₹25–₹50 re-delivery payment via phishing site. (Ref: India Post Advisory)",
        "<b>5. Utility Disconnection Notice:</b> Threatening power disconnection tonight for unpaid bills. (Ref: Cybercrime Portal)",
        "<b>6. Fake Job & Task Scam:</b> YouTube video likes / Telegram investment tasks requiring deposits. (Ref: MHA I4C)",
        "<b>7. Investment & Stock Tip Scam:</b> VIP groups offering pre-IPO shares or 500% returns. (Ref: SEBI Investor Alerts)",
        "<b>8. Lottery & Lucky Prize:</b> Unsolicited car/cash wins demanding processing taxes. (Ref: Cybercrime Portal)",
        "<b>9. Digital Arrest & Impersonation:</b> Fake police/CBI video calls threatening contraband warrants. (Ref: PIB / MHA)",
        "<b>10. Remote Access APK:</b> Coercing installation of AnyDesk/RustDesk to mirror OTPs. (Ref: Cybercrime Portal)",
        "<b>11. Fake Loan App Harassment:</b> Unlicensed instant loan apps blackmailing contacts. (Ref: RBI Working Group)",
        "<b>12. Fake Customer Care:</b> Deceptive search engine results routing victims to scam call centers. (Ref: Consumer Helpline)",
        "<b>13. Fraud Callback & IVR:</b> Automated robocalls claiming unauthorized debits with 'press 1' prompts. (Ref: Cybercrime Portal)",
    ]
    for nl in notes_list:
        story.append(Paragraph(f"• {nl}", bullet_style))

    story.append(Spacer(1, 12))

    # =========================================================================
    # SECTION 4: EMERGENCY CONTAINMENT PROTOCOL
    # =========================================================================
    story.append(Paragraph("4. Emergency Containment Protocol (The First 60 Minutes)", h1_style))
    story.append(
        Paragraph(
            "When a user indicates money was sent, OTP was disclosed, or an app was installed, ScamShield AI "
            "activates its high-priority <b>Emergency Containment Banner</b> before displaying general educational guidance.",
            body_style,
        )
    )
    story.append(
        Paragraph(
            "<b>EMERGENCY PROTOCOL STEPS:</b><br/>"
            "<b>1. Bank Account & Card Freeze:</b> Immediately call your bank's 24x7 emergency helpline (using the verified number printed on the back of your card) to freeze netbanking, UPI, and debit cards.<br/>"
            "<b>2. Dial 1930 Helpline:</b> Call the National Cybercrime Helpline at <b>1930</b> immediately or register at <b>cybercrime.gov.in</b> to initiate an inter-bank transaction freeze on the CFCFRMS portal.<br/>"
            "<b>3. Device Isolation:</b> If an app (like AnyDesk or an APK) was installed, switch your phone to Airplane Mode immediately, disconnect Wi-Fi, and uninstall the malicious application.<br/>"
            "<b>4. Stop Further Transfers:</b> Do not transfer additional funds under any circumstances; government agencies never demand money via video call.<br/>"
            "<b>5. Evidence Preservation:</b> Take screenshots of messages, transaction reference numbers (UTR), recipient UPI IDs, and call logs for formal dispute filing.",
            urgent_callout,
        )
    )

    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 5: EMPIRICAL 4-SYSTEM BENCHMARK EVALUATION
    # =========================================================================
    story.append(PageBreak())  # Clean break for benchmark tables
    story.append(Paragraph("5. Empirical Benchmark Evaluation (Held-Out Test Set)", h1_style))
    story.append(
        Paragraph(
            "Evaluation was conducted strictly on the <b>70 held-out test messages</b> from <code>eval/messages.csv</code> "
            "(rows 61–130) using <b>Gemini 3.1 Flash Lite</b> (uncached, 100% cache misses, temperature 0.0). "
            "The 60 tuning rows were excluded to guarantee zero contamination.",
            body_style,
        )
    )

    # Comparative Performance Table
    eval_tbl_data = [
        [
            Paragraph("Evaluation Metric", tbl_header),
            Paragraph("System A<br/>Plain LLM", tbl_header),
            Paragraph("System B<br/>LLM + OKF Notes", tbl_header),
            Paragraph("System C<br/>Full Agent", tbl_header),
            Paragraph("System D<br/>Rules Only", tbl_header),
        ],
        [
            Paragraph("<b>Scam F1-Score</b>", tbl_cell_bold),
            Paragraph("88.0%", tbl_cell),
            Paragraph("<b>94.3%</b>", tbl_cell_bold),
            Paragraph("86.1%", tbl_cell),
            Paragraph("49.1%", tbl_cell),
        ],
        [
            Paragraph("<b>Scam Recall</b>", tbl_cell_bold),
            Paragraph("97.1% (33/34)", tbl_cell),
            Paragraph("97.1% (33/34)", tbl_cell),
            Paragraph("<b>100.0% (34/34)</b>", tbl_cell_bold),
            Paragraph("41.2% (14/34)", tbl_cell),
        ],
        [
            Paragraph("<b>False Alarm Rate</b>", tbl_cell_bold),
            Paragraph("22.2% (8/36)", tbl_cell),
            Paragraph("<b>8.3% (3/36)</b>", tbl_cell_bold),
            Paragraph("30.6% (11/36)", tbl_cell),
            Paragraph("25.0% (9/36)", tbl_cell),
        ],
        [
            Paragraph("<b>Urgent Recall</b>", tbl_cell_bold),
            Paragraph("<b>100.0% (12/12)</b>", tbl_cell_bold),
            Paragraph("<b>100.0% (12/12)</b>", tbl_cell_bold),
            Paragraph("<b>100.0% (12/12)</b>", tbl_cell_bold),
            Paragraph("25.0% (3/12)", tbl_cell),
        ],
        [
            Paragraph("<b>Scam Type Accuracy</b>", tbl_cell_bold),
            Paragraph("<b>79.4% (27/34)</b>", tbl_cell_bold),
            Paragraph("<b>79.4% (27/34)</b>", tbl_cell_bold),
            Paragraph("35.3% (12/34)*", tbl_cell),
            Paragraph("47.1% (16/34)", tbl_cell),
        ],
        [
            Paragraph("<b>Invented Contacts</b>", tbl_cell_bold),
            Paragraph("<b>0</b>", tbl_cell_bold),
            Paragraph("1", tbl_cell),
            Paragraph("8", tbl_cell),
            Paragraph("<b>0</b>", tbl_cell_bold),
        ],
        [
            Paragraph("<b>API Latency (per call)</b>", tbl_cell_bold),
            Paragraph("4.966s", tbl_cell),
            Paragraph("3.260s", tbl_cell),
            Paragraph("3.193s", tbl_cell),
            Paragraph("<b>0.141s</b>", tbl_cell_bold),
        ],
        [
            Paragraph("<b>Avg Wall Latency / Row</b>", tbl_cell_bold),
            Paragraph("4.970s", tbl_cell),
            Paragraph("3.807s", tbl_cell),
            Paragraph("9.054s", tbl_cell),
            Paragraph("<b>0.141s</b>", tbl_cell_bold),
        ],
        [
            Paragraph("<b>Total Wall-Clock Time</b>", tbl_cell_bold),
            Paragraph("347.9s (~5.8m)", tbl_cell),
            Paragraph("266.5s (~4.4m)", tbl_cell),
            Paragraph("633.7s (~10.5m)", tbl_cell),
            Paragraph("<b>9.9s</b>", tbl_cell_bold),
        ],
        [
            Paragraph("<b>Avg Tool Calls / Req</b>", tbl_cell_bold),
            Paragraph("1.00", tbl_cell),
            Paragraph("1.00", tbl_cell),
            Paragraph("2.46", tbl_cell),
            Paragraph("0.00", tbl_cell),
        ],
    ]
    eval_table = Table(eval_tbl_data, colWidths=[1.9 * inch, 1.25 * inch, 1.35 * inch, 1.25 * inch, 1.25 * inch])
    eval_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ])
    )
    story.append(eval_table)
    story.append(
        Paragraph(
            "<font size=7 color='#64748B'>*Note: System C's scam type accuracy reflects the model generating free-form descriptive titles "
            "(e.g., 'Digital Arrest Scam') rather than canonical slugs (`impersonation_digital_arrest`).</font>",
            body_style,
        )
    )
    story.append(Spacer(1, 10))

    # Group Breakdown Table
    story.append(Paragraph("<b>Breakdown by Challenging Held-Out Slice:</b>", h2_style))
    group_data = [
        [
            Paragraph("Evaluation Slice", tbl_header),
            Paragraph("System A (Plain LLM)", tbl_header),
            Paragraph("System B (LLM + OKF)", tbl_header),
            Paragraph("System C (Full Agent)", tbl_header),
            Paragraph("System D (Rules Only)", tbl_header),
        ],
        [
            Paragraph("<b>Indirect Urgent (5 scams)</b><br/><i>'they asked me to install an app and I did'</i>", tbl_cell),
            Paragraph("Scam: 5/5<br/>Urgent: 5/5", tbl_cell),
            Paragraph("Scam: 5/5<br/>Urgent: 5/5", tbl_cell),
            Paragraph("Scam: 5/5<br/>Urgent: 5/5", tbl_cell),
            Paragraph("Scam: 1/5<br/><b>Urgent: 0/5 (0%)</b>", tbl_cell),
        ],
        [
            Paragraph("<b>Vague Prompts (4 scams, 1 legit)</b><br/><i>'my balance looks different, did something wrong'</i>", tbl_cell),
            Paragraph("Scam: 4/4<br/>False Alarm: 1/1", tbl_cell),
            Paragraph("Scam: 4/4<br/>False Alarm: 1/1", tbl_cell),
            Paragraph("Scam: 4/4<br/>False Alarm: 1/1", tbl_cell),
            Paragraph("<b>Scam: 0/4 (0%)</b><br/>False Alarm: 1/1", tbl_cell),
        ],
        [
            Paragraph("<b>Hinglish & Kannada (10 scams)</b><br/>Regional dialect fraud prompts", tbl_cell),
            Paragraph("Scam: 9/10<br/>Urgent: 3/3", tbl_cell),
            Paragraph("Scam: 9/10<br/>Urgent: 3/3", tbl_cell),
            Paragraph("<b>Scam: 10/10 (100%)</b><br/>Urgent: 3/3", tbl_cell),
            Paragraph("<b>Scam: 1/10 (10%)</b><br/>Urgent: 0/3", tbl_cell),
        ],
        [
            Paragraph("<b>Legitimate Alerts (36 rows)</b><br/>Authentic bank debit & OTP notices", tbl_cell),
            Paragraph("False Alarms:<br/>8/36 (22.2%)", tbl_cell),
            Paragraph("False Alarms:<br/><b>3/36 (8.3%)</b>", tbl_cell_bold),
            Paragraph("False Alarms:<br/>11/36 (30.6%)", tbl_cell),
            Paragraph("False Alarms:<br/>9/36 (25.0%)", tbl_cell),
        ],
    ]
    group_table = Table(group_data, colWidths=[2.1 * inch, 1.25 * inch, 1.25 * inch, 1.25 * inch, 1.15 * inch])
    group_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SECONDARY),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ])
    )
    story.append(group_table)
    story.append(Spacer(1, 12))

    # =========================================================================
    # SECTION 6: REPRESENTATIVE FAILURE CASES
    # =========================================================================
    story.append(Paragraph("6. Known Failure Modes Across Systems", h1_style))
    failures = [
        "<b>System A (Plain LLM):</b> Over-flagged legitimate HDFC bank debit notices (ID 76) and salary deposits (ID 79) as scams due to the presence of reporting keywords, resulting in a 22.2% false positive rate.",
        "<b>System B (LLM + OKF Notes):</b> Achieved best overall performance (94.3% F1, 8.3% false alarms), but misclassified subtle multi-step lottery vouchers asking for card numbers as <code>otp_theft</code> instead of <code>lottery_prize</code> (ID 105).",
        "<b>System C (Full Agent with Tools):</b> Achieved 100% scam recall, but generated human-readable titles ('Digital Arrest Scam') rather than machine slugs, lowering type accuracy to 35.3%, and suffered higher false alarms (30.6%) due to exploratory tool loops.",
        "<b>System D (Rules Only):</b> Collapsed on indirect urgent scenarios (0/5 urgent recall on prompts like 'they asked me to install an app and I did') and missed 9 of 10 Hinglish/Kannada messages (10% recall) due to strict regex dependencies.",
    ]
    for f in failures:
        story.append(Paragraph(f"• {f}", bullet_style))

    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 7: 12-SLIDE PRESENTATION OUTLINE
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("7. Ready-to-Use 12-Slide Presentation Outline", h1_style))
    story.append(
        Paragraph(
            "Below is the complete slide-by-slide outline for pitch decks, academic viva, or executive presentations:",
            body_style,
        )
    )

    slides = [
        ("Slide 1: Title & Vision", "ScamShield AI: An OKF-Grounded Assistant for Real-Time Fraud Defense & Rapid Emergency Containment in India's Digital Payments Ecosystem."),
        ("Slide 2: The Problem", "₹22,845.73 crore reported lost to cyber financial frauds in India during 2024 (MHA / CFCFRMS). Victims panic during the critical 'Golden Hour'."),
        ("Slide 3: Our Solution", "Multi-layered defense: Instant NLP extraction, calibrated verdicts (SCAM / LEGIT), OKF knowledge grounding, and immediate emergency account freezing."),
        ("Slide 4: Architecture", "Hybrid Dual-Engine pipeline: 100% offline deterministic rules fallback (0.14s) paired with an agentic Gemini loop with strict security boundaries."),
        ("Slide 5: NLP Entity Extraction", "Detects Indian mobile numbers (+91), UPI VPAs, masked card identifiers (XX4921), amounts (₹/INR/Lakhs), and shortened URLs (bit.ly)."),
        ("Slide 6: Google OKF Standard", "13 standardized fraud typologies built strictly on Google's Open Knowledge Format (OKF 1.0.0) referencing official RBI, SEBI, NPCI, and PIB advisories."),
        ("Slide 7: Emergency Protocol", "Triggered automatically when money was sent or OTP was shared: Bank account freeze, 1930 Cybercrime Helpline reporting, and airplane mode activation."),
        ("Slide 8: Empirical Benchmark", "Evaluated on 70 held-out test messages: 100% urgent recall, lowest false alarms (8.3%) and 94.3% F1 with OKF grounding (System B) vs 49.1% for rules."),
        ("Slide 9: Security Guardrails", "Prompt injection defense (<message> delimiters), automatic PII masking (phones, cards, OTPs), zero live URL fetching to prevent drive-by malware."),
        ("Slide 10: User Experience", "Clean Streamlit web interface: simple text / screenshot paste, color-coded verdict banners, transparent execution traces, and follow-up Q&A."),
        ("Slide 11: Competitive Edge", "Unlike static caller ID filters (Truecaller) or hallucination-prone generic bots, ScamShield provides grounded verification and rapid emergency response."),
        ("Slide 12: Roadmap & Conclusion", "Future milestones: Multilingual Whisper speech recognition for live scam call audio and a lightweight browser extension for real-time web phishing alerts."),
    ]

    for title, desc in slides:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", bullet_style))

    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 8: LIMITATIONS & REPRODUCTION
    # =========================================================================
    story.append(Paragraph("8. Honest Limitations & Reproduction Guide", h1_style))
    story.append(
        Paragraph(
            "<b>Honest System Limitations:</b><br/>"
            "• <b>Synthetic Dataset:</b> The 130-message dataset is synthetic (modeled after published police advisories); real-world adversarial attacks evolve rapidly.<br/>"
            "• <b>Draft Status of Notes:</b> All 13 OKF notes carry draft status pending formal regulatory gazette peer-review.<br/>"
            "• <b>Offline Heuristics:</b> Heuristic URL inspection cannot detect zero-day phishing pages on newly registered benign domains without live threat feeds.<br/>"
            "• <b>Guidance Only:</b> ScamShield provides educational guidance; it cannot directly execute banking API freezes or police FIRs.",
            body_style,
        )
    )

    story.append(
        Paragraph(
            "<b>Reproduction Commands (PowerShell / Windows):</b><br/>"
            "<code>pip install -r requirements.txt</code><br/>"
            "<code>python -m pytest -v</code> (Runs all 42 tests)<br/>"
            "<code>streamlit run app/streamlit_app.py</code> (Launches Web UI at localhost:8501)",
            code_style,
        )
    )

    # Build Document to primary path, then copy to other destinations
    primary_path = output_paths[0]
    Path(primary_path).parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(primary_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=50,
        bottomMargin=50,
    )
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Generated PDF: {primary_path} ({os.path.getsize(primary_path) / 1024:.1f} KB)")

    import shutil
    for out_path in output_paths[1:]:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(primary_path, out_path)
        print(f"Copied PDF: {out_path} ({os.path.getsize(out_path) / 1024:.1f} KB)")


if __name__ == "__main__":
    downloads = Path(os.environ["USERPROFILE"]) / "Downloads" / "ScamShield_AI_Complete_Report.pdf"
    repo_pdf = Path(__file__).resolve().parent.parent / "ScamShield_AI_Complete_Report.pdf"
    brain_pdf = Path(r"C:\Users\sumangala vastrad\.gemini\antigravity\brain\09daac2a-7dec-448a-b133-8694d9761c47\ScamShield_AI_Complete_Report.pdf")

    build_pdf([downloads, repo_pdf, brain_pdf])
