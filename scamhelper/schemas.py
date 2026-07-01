"""Data structures and schemas for ScamShield AI / Scam and Fraud Helper."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple


# Standard calibrated verdicts per specification
VERDICT_LIKELY_SCAM = "Likely scam"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_NOT_SURE = "Not sure"
VERDICT_LIKELY_SAFE = "Likely safe"


@dataclass
class EntitySignal:
    type: str  # url, shortened_url, phone, upi_id, amount, brand, urgency, sensitive_data, money_already_sent, card_suffix, ivr_option, entity
    value: str
    span: Tuple[int, int]

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "value": self.value, "span": list(self.span)}


@dataclass
class ExtractionResult:
    text: str
    signals: List[EntitySignal] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    shortened_urls: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    upi_ids: List[str] = field(default_factory=list)
    amounts: List[str] = field(default_factory=list)
    card_suffixes: List[str] = field(default_factory=list)
    ivr_options: List[str] = field(default_factory=list)
    brands: List[str] = field(default_factory=list)
    urgency_phrases: List[str] = field(default_factory=list)
    sensitive_data_requests: List[str] = field(default_factory=list)
    money_already_sent_phrases: List[str] = field(default_factory=list)
    language: str = "en"
    spacy_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "signals": [s.to_dict() for s in self.signals],
            "urls": self.urls,
            "shortened_urls": self.shortened_urls,
            "phone_numbers": self.phone_numbers,
            "upi_ids": self.upi_ids,
            "amounts": self.amounts,
            "card_suffixes": self.card_suffixes,
            "ivr_options": self.ivr_options,
            "brands": self.brands,
            "urgency_phrases": self.urgency_phrases,
            "sensitive_data_requests": self.sensitive_data_requests,
            "money_already_sent_phrases": self.money_already_sent_phrases,
            "language": self.language,
            "spacy_available": self.spacy_available,
        }


@dataclass
class URLAnalysis:
    url: str
    is_shortened: bool = False
    is_ip_host: bool = False
    has_bank_lookalike: bool = False
    unusual_tld: bool = False
    many_subdomains: bool = False
    many_hyphens_or_digits: bool = False
    is_http: bool = False
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NoteSummary:
    scam_type: str
    title: str
    status: str
    red_flags: List[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TraceStep:
    tool: str
    args: Dict[str, Any]
    result_summary: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    verdict: str  # Likely scam, Suspicious, Likely safe, Not sure
    confidence: str = "high"  # high, medium, low (aligned with verdict)
    scam_type: Optional[str] = None
    red_flags: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    urgent: bool = False
    urgent_banner: bool = False
    urgent_steps: List[str] = field(default_factory=list)
    uncertainty: str = "low"
    note_title: Optional[str] = None
    note_status: Optional[str] = None
    sources: List[Dict[str, Any]] = field(default_factory=list)
    signals: List[Dict[str, Any]] = field(default_factory=list)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    engine_used: str = "Rule-Based (offline)"
    is_llm_based: bool = False
    rule_score: int = 0
    disclaimer: str = (
        "This is guidance, not a guarantee. Verify with your bank and the official "
        "cybercrime portal before acting."
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
