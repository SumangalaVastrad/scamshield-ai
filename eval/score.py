"""Metric computation for ScamShield AI Evaluation.

Computes:
- Scam vs. Legit Precision, Recall, F1, False-Positive Rate
- Urgent-Path Recall and Precision
- Scam-Type Classification Accuracy
- Invented Contact Count (Helpline/URL hallucination detector)
- Average Latency and Tool Calls
"""

import re
from typing import List, Dict, Any, Set, Tuple, Optional


def compute_metrics(
    eval_rows: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    known_contacts: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Compute rigorous evaluation metrics for a system's predictions against ground truth.
    """
    known_contacts = known_contacts or set()

    tp = fp = fn = tn = 0
    urgent_tp = urgent_fp = urgent_fn = urgent_tn = 0
    scam_type_correct = 0
    scam_type_total = 0
    total_latency = 0.0
    total_tool_calls = 0
    invented_contacts = 0

    phone_regex = re.compile(r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b")
    url_regex = re.compile(r"https?://[^\s<>'\"]+")

    for gold, pred in zip(eval_rows, predictions):
        is_scam_gold = gold["label"].lower() == "scam"
        urgent_gold = str(gold["urgent_gold"]).lower() in ("true", "1", "yes")
        gold_type = gold.get("scam_type_gold", "").strip()

        # Prediction values
        verdict = pred.get("verdict", "").upper()
        is_scam_pred = verdict in ("SCAM", "LIKELY SCAM")
        urgent_pred = bool(pred.get("urgent", False))
        pred_type = pred.get("scam_type") or ""

        # Latency & Tool calls
        total_latency += float(pred.get("latency", 0.0))
        total_tool_calls += int(pred.get("tool_calls_count", 0))

        # Scam vs Legit Classification
        if is_scam_gold and is_scam_pred:
            tp += 1
        elif not is_scam_gold and is_scam_pred:
            fp += 1
        elif is_scam_gold and not is_scam_pred:
            fn += 1
        else:
            tn += 1

        # Urgent Path Recall / Precision
        if urgent_gold and urgent_pred:
            urgent_tp += 1
        elif not urgent_gold and urgent_pred:
            urgent_fp += 1
        elif urgent_gold and not urgent_pred:
            urgent_fn += 1
        else:
            urgent_tn += 1

        # Scam Type Accuracy
        if is_scam_gold and gold_type:
            scam_type_total += 1
            if pred_type.lower() == gold_type.lower():
                scam_type_correct += 1

        # Check for Hallucinated / Invented Contacts in steps
        answer_text = " ".join(pred.get("steps", [])) + " " + " ".join(pred.get("urgent_steps", []))
        for phone in phone_regex.findall(answer_text):
            if phone not in known_contacts and "1930" not in phone:
                invented_contacts += 1
        for url in url_regex.findall(answer_text):
            if url not in known_contacts:
                invented_contacts += 1

    total = len(eval_rows)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    urgent_precision = urgent_tp / (urgent_tp + urgent_fp) if (urgent_tp + urgent_fp) > 0 else 0.0
    urgent_recall = urgent_tp / (urgent_tp + urgent_fn) if (urgent_tp + urgent_fn) > 0 else 0.0

    scam_type_acc = scam_type_correct / scam_type_total if scam_type_total > 0 else 0.0
    avg_latency = total_latency / total if total > 0 else 0.0
    avg_tool_calls = total_tool_calls / total if total > 0 else 0.0

    return {
        "total_messages": total,
        "scam_precision": round(precision, 4),
        "scam_recall": round(recall, 4),
        "scam_f1": round(f1, 4),
        "false_positive_rate": round(fp_rate, 4),
        "urgent_precision": round(urgent_precision, 4),
        "urgent_recall": round(urgent_recall, 4),
        "scam_type_accuracy": round(scam_type_acc, 4),
        "scam_type_correct": scam_type_correct,
        "scam_type_evaluated": scam_type_total,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "urgent_tp": urgent_tp,
        "urgent_fp": urgent_fp,
        "urgent_fn": urgent_fn,
        "urgent_tn": urgent_tn,
        "invented_contacts": invented_contacts,
        "avg_latency_sec": round(avg_latency, 3),
        "avg_tool_calls": round(avg_tool_calls, 2),
    }
