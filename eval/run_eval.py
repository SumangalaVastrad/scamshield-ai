"""Evaluation Runner comparing 4 Systems on the Held-Out Test Set:
  System A: Plain LLM (Zero-shot, 13 scam-type choices, no notes, no tools)
  System B: LLM + OKF Notes Retrieved (RAG, 13 scam-type choices, no tools)
  System C: Full Agent with Tools (Bounded tool-calling loop, OKF notes, safety arbitration)
  System D: Rules Only (Offline heuristic scoring engine)

Features:
- Enforces real Gemini API calls (stops with MissingAPIKeyError if key missing, NO silent fallback).
- Dynamic model discovery (queries API for active Flash-type models, e.g. gemini-3.1-flash-lite).
- Exponential backoff retry on 429 / 503 rate limits.
- Resumable checkpointing per system so interrupted runs resume without losing progress.
- Dual latency tracking: per-call network API latency (excluding backoff) and total wall-clock latency.
- Group-level breakdown: indirect urgent, vague, Hinglish/Kannada, legitimate alerts.
- Saves all raw model outputs (prompts, responses, model names, tool calls) to eval/results/audit_*.jsonl.
- Generates 5 failure examples per system with short reasons.
"""

import sys
import os
import csv
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scamhelper.rules import evaluate_rules
from scamhelper.agent import ScamShieldAgent
from scamhelper.schemas import AnalysisResult
from scamhelper.llm import LLMWrapper, MissingAPIKeyError
from scamhelper.tools import _get_bundle
from eval.score import compute_metrics

VALID_SCAM_TYPES = [
    "fake_kyc",
    "otp_theft",
    "upi_refund",
    "parcel_fee",
    "utility_disconnection",
    "fake_job",
    "investment_scam",
    "lottery_prize",
    "impersonation_digital_arrest",
    "remote_access_apk",
    "fake_loan_app",
    "fake_customer_care",
    "fraud_callback",
]

SCAM_TYPES_PROMPT_LIST = ", ".join(f'"{st}"' for st in VALID_SCAM_TYPES)


def load_checkpoint(checkpoint_file: Path) -> Dict[str, Dict[str, Any]]:
    """Load previously completed row results from JSONL checkpoint."""
    records = {}
    if checkpoint_file.exists():
        with open(checkpoint_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        records[str(data["id"])] = data
                    except Exception:
                        pass
    return records


def save_checkpoint_row(checkpoint_file: Path, record: Dict[str, Any]):
    """Append a completed row result to JSONL checkpoint."""
    checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
    with open(checkpoint_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def append_audit_log(audit_file: Path, entry: Dict[str, Any]):
    """Append raw prompt/response audit record."""
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ==============================================================================
# SYSTEM A: PLAIN LLM (No notes, no tools, 13 scam-type choices)
# ==============================================================================
def run_system_a_plain_llm(
    rows: List[Dict[str, Any]],
    llm: LLMWrapper,
    log_records: List[Dict[str, Any]],
    checkpoint_file: Path,
    audit_file: Path,
) -> List[Dict[str, Any]]:
    """System A: Plain LLM zero-shot classification."""
    if not llm.is_available():
        raise MissingAPIKeyError("System A (Plain LLM) requires a valid GEMINI_API_KEY in .env.")

    system_prompt = (
        "You are an expert scam and fraud analysis assistant.\n"
        "Evaluate whether the provided user message is a scam.\n"
        f"Allowed scam_type values: [{SCAM_TYPES_PROMPT_LIST}, null].\n"
        "Allowed verdict values: \"SCAM\", \"LIKELY SCAM\", \"UNSURE\", \"LOOKS LEGITIMATE\".\n\n"
        "Output ONLY a raw JSON object with this exact schema:\n"
        "{\n"
        '  "verdict": "SCAM" | "LIKELY SCAM" | "UNSURE" | "LOOKS LEGITIMATE",\n'
        '  "scam_type": "<one of the allowed scam types or null>",\n'
        '  "urgent": true | false,\n'
        '  "red_flags": ["<red flag 1>", "..."],\n'
        '  "steps": ["<step 1>", "..."]\n'
        "}"
    )

    checkpoint = load_checkpoint(checkpoint_file)
    predictions = []

    for r in rows:
        row_id = str(r["id"])
        if row_id in checkpoint:
            cached = checkpoint[row_id]
            predictions.append(cached)
            log_records.append({
                "id": row_id,
                "system": "System A: Plain LLM",
                "model": cached.get("model", llm.model_name),
                "cache": "RESUME_CHECKPOINT",
                "api_latency": cached.get("api_latency", 0.0),
                "wall_latency": cached.get("wall_latency", 0.0),
                "llm_calls": cached.get("tool_calls_count", 1),
            })
            continue

        llm.reset_stats()
        t_wall = time.time()
        prompt = f"User message to analyze:\n{r['text']}"
        res_json = llm.generate_json(prompt, system_prompt)
        wall_lat = time.time() - t_wall
        api_lat = getattr(llm, "last_api_latency", wall_lat)

        pred = {
            "id": r["id"],
            "model": llm.model_name,
            "verdict": res_json.get("verdict", "UNSURE"),
            "scam_type": res_json.get("scam_type"),
            "urgent": bool(res_json.get("urgent", False)),
            "steps": res_json.get("steps", []),
            "urgent_steps": [],
            "latency": api_lat,  # Reported per-API call network latency
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "tool_calls_count": llm.last_call_count,
        }
        predictions.append(pred)
        save_checkpoint_row(checkpoint_file, pred)

        append_audit_log(audit_file, {
            "id": r["id"],
            "system": "System A",
            "model": llm.model_name,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "raw_response": res_json,
            "api_latency": api_lat,
            "wall_latency": wall_lat,
        })

        log_records.append({
            "id": r["id"],
            "system": "System A: Plain LLM",
            "model": llm.model_name,
            "cache": "HIT" if llm.last_cache_hit else "MISS",
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "llm_calls": llm.last_call_count,
        })
        time.sleep(1.0)

    return predictions


# ==============================================================================
# SYSTEM B: LLM + OKF NOTES RETRIEVED (RAG, no tools)
# ==============================================================================
def run_system_b_llm_okf(
    rows: List[Dict[str, Any]],
    llm: LLMWrapper,
    log_records: List[Dict[str, Any]],
    checkpoint_file: Path,
    audit_file: Path,
) -> List[Dict[str, Any]]:
    """System B: RAG with offline retrieval of OKF notes injected into prompt."""
    if not llm.is_available():
        raise MissingAPIKeyError("System B (LLM + OKF Notes) requires a valid GEMINI_API_KEY in .env.")

    bundle = _get_bundle()
    checkpoint = load_checkpoint(checkpoint_file)
    predictions = []

    for r in rows:
        row_id = str(r["id"])
        if row_id in checkpoint:
            cached = checkpoint[row_id]
            predictions.append(cached)
            log_records.append({
                "id": row_id,
                "system": "System B: LLM + OKF Notes",
                "model": cached.get("model", llm.model_name),
                "cache": "RESUME_CHECKPOINT",
                "api_latency": cached.get("api_latency", 0.0),
                "wall_latency": cached.get("wall_latency", 0.0),
                "llm_calls": cached.get("tool_calls_count", 1),
            })
            continue

        # Retrieve top 2 matching OKF notes offline
        t_wall = time.time()
        matches = bundle.search_notes(r["text"], top_k=2)
        retrieved_context = ""
        for m in matches:
            note = bundle.get_note(m.scam_type)
            if note:
                retrieved_context += (
                    f"\n--- Reference Pattern: {note.title} (ID: {note.scam_type}) ---\n"
                    f"Red Flags: {', '.join(note.red_flags[:4])}\n"
                    f"Summary: {note.body[:350]}\n"
                )

        rag_prompt = (
            "You are an expert scam analysis assistant grounded in the following reference fraud knowledge notes:\n"
            f"{retrieved_context or 'No specific reference note matched.'}\n\n"
            f"Allowed scam_type values: [{SCAM_TYPES_PROMPT_LIST}, null].\n"
            "Allowed verdict values: \"SCAM\", \"LIKELY SCAM\", \"UNSURE\", \"LOOKS LEGITIMATE\".\n\n"
            "Analyze the message. Ground your classification in the reference patterns if applicable.\n"
            "Output ONLY a raw JSON object with keys: verdict, scam_type, urgent, red_flags, steps."
        )

        llm.reset_stats()
        user_prompt = f"User message to analyze:\n{r['text']}"
        res_json = llm.generate_json(user_prompt, rag_prompt)
        wall_lat = time.time() - t_wall
        api_lat = getattr(llm, "last_api_latency", wall_lat)

        pred = {
            "id": r["id"],
            "model": llm.model_name,
            "verdict": res_json.get("verdict", "UNSURE"),
            "scam_type": res_json.get("scam_type"),
            "urgent": bool(res_json.get("urgent", False)),
            "steps": res_json.get("steps", []),
            "urgent_steps": [],
            "latency": api_lat,
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "tool_calls_count": llm.last_call_count,
        }
        predictions.append(pred)
        save_checkpoint_row(checkpoint_file, pred)

        append_audit_log(audit_file, {
            "id": r["id"],
            "system": "System B",
            "model": llm.model_name,
            "retrieved_context": retrieved_context,
            "prompt": user_prompt,
            "system_prompt": rag_prompt,
            "raw_response": res_json,
            "api_latency": api_lat,
            "wall_latency": wall_lat,
        })

        log_records.append({
            "id": r["id"],
            "system": "System B: LLM + OKF Notes",
            "model": llm.model_name,
            "cache": "HIT" if llm.last_cache_hit else "MISS",
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "llm_calls": llm.last_call_count,
        })
        time.sleep(1.0)

    return predictions


# ==============================================================================
# SYSTEM C: FULL AGENT WITH TOOLS (Bounded loop, injection defense)
# ==============================================================================
def run_system_c_agent(
    rows: List[Dict[str, Any]],
    agent: ScamShieldAgent,
    log_records: List[Dict[str, Any]],
    checkpoint_file: Path,
    audit_file: Path,
) -> List[Dict[str, Any]]:
    """System C: Full Agentic Loop with tools and arbitration."""
    if not agent.llm.is_available():
        raise MissingAPIKeyError("System C (Full Agent) requires a valid GEMINI_API_KEY in .env.")

    checkpoint = load_checkpoint(checkpoint_file)
    predictions = []

    for r in rows:
        row_id = str(r["id"])
        if row_id in checkpoint:
            cached = checkpoint[row_id]
            predictions.append(cached)
            log_records.append({
                "id": row_id,
                "system": "System C: Full Agent",
                "model": cached.get("model", agent.llm.model_name),
                "cache": "RESUME_CHECKPOINT",
                "api_latency": cached.get("api_latency", 0.0),
                "wall_latency": cached.get("wall_latency", 0.0),
                "llm_calls": cached.get("tool_calls_count", 1),
            })
            continue

        agent.llm.reset_stats()
        t_wall = time.time()
        res = agent.analyze(r["text"], strict_llm=True)
        wall_lat = time.time() - t_wall
        api_lat = getattr(agent.llm, "last_api_latency", wall_lat / max(1, agent.llm.last_call_count))
        tool_count = len([t for t in res.trace if t["tool"] not in ("final_answer", "llm_call_error")])

        pred = {
            "id": r["id"],
            "model": agent.llm.model_name,
            "verdict": res.verdict,
            "scam_type": res.scam_type,
            "urgent": res.urgent,
            "steps": res.steps,
            "urgent_steps": res.urgent_steps,
            "latency": api_lat,
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "tool_calls_count": max(agent.llm.last_call_count, tool_count + 1),
            "red_flags": res.red_flags,
            "trace": res.trace,
        }
        predictions.append(pred)
        save_checkpoint_row(checkpoint_file, pred)

        append_audit_log(audit_file, {
            "id": r["id"],
            "system": "System C",
            "model": agent.llm.model_name,
            "input_text": r["text"],
            "verdict": res.verdict,
            "scam_type": res.scam_type,
            "urgent": res.urgent,
            "trace": res.trace,
            "tool_calls_count": pred["tool_calls_count"],
            "api_latency": api_lat,
            "wall_latency": wall_lat,
        })

        log_records.append({
            "id": r["id"],
            "system": "System C: Full Agent",
            "model": agent.llm.model_name,
            "cache": "HIT" if agent.llm.last_cache_hit else "MISS",
            "api_latency": round(api_lat, 4),
            "wall_latency": round(wall_lat, 4),
            "llm_calls": pred["tool_calls_count"],
        })
        time.sleep(1.0)

    return predictions


# ==============================================================================
# SYSTEM D: RULES-ONLY OFFLINE ENGINE
# ==============================================================================
def run_system_d_rules(
    rows: List[Dict[str, Any]],
    log_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """System D: Deterministic rule-based scoring without LLM or network."""
    predictions = []
    for r in rows:
        t0 = time.time()
        res = evaluate_rules(r["text"])
        lat = time.time() - t0

        pred = {
            "id": r["id"],
            "model": "rule_engine_offline",
            "verdict": res.verdict,
            "scam_type": res.scam_type,
            "urgent": res.urgent,
            "steps": res.steps,
            "urgent_steps": res.urgent_steps,
            "latency": lat,
            "api_latency": lat,
            "wall_latency": lat,
            "tool_calls_count": 0,
        }
        predictions.append(pred)
        log_records.append({
            "id": r["id"],
            "system": "System D: Rules Only",
            "model": "rule_engine_offline",
            "cache": "N/A (offline)",
            "api_latency": round(lat, 4),
            "wall_latency": round(lat, 4),
            "llm_calls": 0,
        })
    return predictions


# ==============================================================================
# GROUP BREAKDOWN HELPER
# ==============================================================================
def compute_group_metrics(rows: List[Dict[str, Any]], preds: List[Dict[str, Any]], known_contacts: set) -> Dict[str, Any]:
    """Breakdown metrics into groups: indirect urgent, vague, hinglish/kannada, legitimate."""
    groups = {
        "Indirect Urgent (IDs 101-105)": lambda r: 101 <= int(r["id"]) <= 105,
        "Vague Cases (IDs 106-110)": lambda r: 106 <= int(r["id"]) <= 110,
        "Hinglish & Kannada (IDs 111-120)": lambda r: 111 <= int(r["id"]) <= 120,
        "Legitimate Alerts (All Legit)": lambda r: r["label"].lower() == "legit",
        "Overall Held-Out Set (All 70)": lambda r: True,
    }

    group_results = {}
    for gname, filter_fn in groups.items():
        g_rows = []
        g_preds = []
        for r, p in zip(rows, preds):
            if filter_fn(r):
                g_rows.append(r)
                g_preds.append(p)
        if g_rows:
            group_results[gname] = compute_metrics(g_rows, g_preds, known_contacts)
    return group_results


# ==============================================================================
# MAIN EVALUATION PIPELINE
# ==============================================================================
def main():
    print("=" * 70)
    print(" ScamShield AI - 4-System Empirical Evaluation Benchmark")
    print("=" * 70)

    eval_file = repo_root / "eval" / "messages.csv"
    results_dir = repo_root / "eval" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    if not eval_file.exists():
        print(f"Error: Evaluation dataset not found at {eval_file}")
        sys.exit(1)

    all_rows: List[Dict[str, Any]] = []
    with open(eval_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            all_rows.append(r)

    # Filter for held-out test split
    held_out_rows = [r for r in all_rows if r.get("split", "held_out").lower() == "held_out"]
    if not held_out_rows:
        held_out_rows = all_rows

    print(f"Loaded {len(all_rows)} total messages. Running on {len(held_out_rows)} held-out test messages.")

    # Load contacts
    contacts_file = repo_root / "data" / "contacts.yaml"
    known_contacts = set()
    if contacts_file.exists():
        try:
            import yaml
            with open(contacts_file, "r", encoding="utf-8") as f:
                cdata = yaml.safe_load(f) or {}
                for v in cdata.values():
                    if isinstance(v, dict):
                        for sub_v in v.values():
                            if isinstance(sub_v, str) and not sub_v.startswith("[FILL"):
                                known_contacts.add(sub_v)
        except Exception:
            pass

    log_records: List[Dict[str, Any]] = []

    # 1. Run System D (Rules Only) first - offline, always works
    print("\n[1/4] Running System D (Rules-Only Offline Engine)...")
    preds_d = run_system_d_rules(held_out_rows, log_records)
    metrics_d = compute_metrics(held_out_rows, preds_d, known_contacts)

    # 2. Setup LLM client and verify API key
    llm = LLMWrapper(provider="gemini", use_cache=False)
    if not llm.is_available():
        print("\n" + "!" * 70)
        print("NOTICE: GEMINI_API_KEY is not set in .env.")
        print("System D (Rules Only) evaluated successfully.")
        print("Systems A, B, C require a valid GEMINI_API_KEY and will be skipped.")
        print("!" * 70)
        return

    # Discover active Flash model via SDK/REST
    discovered_model = llm.discover_model()
    print(f"Discovered active Gemini model: {discovered_model}")

    # Checkpoint and Audit paths
    cp_a = results_dir / "checkpoint_system_a.jsonl"
    cp_b = results_dir / "checkpoint_system_b.jsonl"
    cp_c = results_dir / "checkpoint_system_c.jsonl"

    audit_a = results_dir / "audit_system_a.jsonl"
    audit_b = results_dir / "audit_system_b.jsonl"
    audit_c = results_dir / "audit_system_c.jsonl"

    # 3. Run System A (Plain LLM)
    print(f"\n[2/4] Running System A (Plain LLM - {discovered_model})...")
    preds_a = run_system_a_plain_llm(held_out_rows, llm, log_records, cp_a, audit_a)
    metrics_a = compute_metrics(held_out_rows, preds_a, known_contacts)

    # 4. Run System B (LLM + OKF Notes)
    print(f"\n[3/4] Running System B (LLM + OKF Notes Retrieved - {discovered_model})...")
    preds_b = run_system_b_llm_okf(held_out_rows, llm, log_records, cp_b, audit_b)
    metrics_b = compute_metrics(held_out_rows, preds_b, known_contacts)

    # 5. Run System C (Full Agent with Tools)
    print(f"\n[4/4] Running System C (Full Agent with Tools - {discovered_model})...")
    agent = ScamShieldAgent(llm)
    preds_c = run_system_c_agent(held_out_rows, agent, log_records, cp_c, audit_c)
    metrics_c = compute_metrics(held_out_rows, preds_c, known_contacts)

    # Comparison Table
    systems = [
        ("System A: Plain LLM", metrics_a, preds_a),
        ("System B: LLM + OKF Notes", metrics_b, preds_b),
        ("System C: Full Agent", metrics_c, preds_c),
        ("System D: Rules Only", metrics_d, preds_d),
    ]

    table_data = []
    for name, m, _ in systems:
        scam_tot = m['tp'] + m['fn']
        legit_tot = m['fp'] + m['tn']
        urg_tot = m['urgent_tp'] + m['urgent_fn']
        type_tot = m['scam_type_evaluated']

        table_data.append({
            "System": name,
            "Scam F1": f"{m['scam_f1'] * 100:.1f}%",
            "Scam Recall": f"{m['scam_recall'] * 100:.1f}% ({m['tp']}/{scam_tot})",
            "False Alarms": f"{m['false_positive_rate'] * 100:.1f}% ({m['fp']}/{legit_tot})",
            "Urgent Recall": f"{m['urgent_recall'] * 100:.1f}% ({m['urgent_tp']}/{urg_tot})",
            "Type Accuracy": f"{m['scam_type_accuracy'] * 100:.1f}% ({m['scam_type_correct']}/{type_tot})",
            "Invented Contacts": m["invented_contacts"],
            "API Latency (s)": f"{m['avg_latency_sec']:.3f}",
            "Avg Tool Calls": f"{m['avg_tool_calls']:.2f}",
        })

    print("\n" + "=" * 135)
    print(f"{'System':<25} | {'Scam F1':<8} | {'Scam Recall':<16} | {'False Alarms':<16} | {'Urgent Recall':<16} | {'Type Acc':<16} | {'API Latency':<11} | {'Halluc':<6}")
    print("-" * 135)
    for td in table_data:
        print(f"{td['System']:<25} | {td['Scam F1']:<8} | {td['Scam Recall']:<16} | {td['False Alarms']:<16} | {td['Urgent Recall']:<16} | {td['Type Accuracy']:<16} | {td['API Latency (s)']:<11} | {td['Invented Contacts']:<6}")
    print("=" * 135)

    # Group Breakdowns
    group_data = {}
    print("\n" + "=" * 80)
    print(" GROUP BREAKDOWN (Raw Counts across Challenging Test Slices)")
    print("=" * 80)
    for sname, _, spreds in systems:
        gmetrics = compute_group_metrics(held_out_rows, spreds, known_contacts)
        group_data[sname] = gmetrics
        print(f"\n[{sname}]")
        for gname, gm in gmetrics.items():
            sc_tot = gm['tp'] + gm['fn']
            fa_tot = gm['fp'] + gm['tn']
            u_tot = gm['urgent_tp'] + gm['urgent_fn']
            print(f"  - {gname:<35}: Scam Rec={gm['tp']}/{sc_tot} | False Alarms={gm['fp']}/{fa_tot} | Urgent Rec={gm['urgent_tp']}/{u_tot}")

    # Extract 5 Failure Examples Per System
    failures_by_system = {}
    for sname, _, spreds in systems:
        s_failures = []
        for gold, pred in zip(held_out_rows, spreds):
            is_scam_gold = gold["label"].lower() == "scam"
            is_scam_pred = pred["verdict"].upper() in ("SCAM", "LIKELY SCAM")
            urgent_gold = str(gold["urgent_gold"]).lower() in ("true", "1", "yes")
            urgent_pred = bool(pred.get("urgent", False))
            gold_type = gold.get("scam_type_gold", "").strip()
            pred_type = pred.get("scam_type") or ""

            reasons = []
            if is_scam_gold and not is_scam_pred:
                reasons.append(f"Missed scam (False Negative: expected scam, got {pred['verdict']})")
            elif not is_scam_gold and is_scam_pred:
                reasons.append(f"False alarm on legitimate message (False Positive: flagged as {pred['verdict']})")
            if urgent_gold and not urgent_pred:
                reasons.append("Failed to escalate urgent breach (missed urgent flag)")
            if is_scam_gold and gold_type and pred_type.lower() != gold_type.lower():
                reasons.append(f"Wrong scam type (expected '{gold_type}', predicted '{pred_type}')")

            if reasons:
                s_failures.append({
                    "id": gold["id"],
                    "text": gold["text"][:110],
                    "expected": f"label={gold['label']}, urgent={urgent_gold}, type={gold_type or 'None'}",
                    "predicted": f"verdict={pred['verdict']}, urgent={urgent_pred}, type={pred_type or 'None'}",
                    "reasons": "; ".join(reasons)
                })
        failures_by_system[sname] = s_failures[:5]

    # Save detailed JSON metrics
    metrics_output = {
        "model_used": discovered_model,
        "split_evaluated": "held_out",
        "held_out_count": len(held_out_rows),
        "metrics_table": table_data,
        "group_breakdown": group_data,
        "failures_sample": failures_by_system,
        "metrics_raw": {
            "system_a": metrics_a,
            "system_b": metrics_b,
            "system_c": metrics_c,
            "system_d": metrics_d,
        },
    }

    with open(results_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_output, f, indent=2)

    with open(results_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(metrics_output, f, indent=2)

    # Save row-by-row log
    if log_records:
        with open(results_dir / "eval_log.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "system", "model", "cache", "api_latency", "wall_latency", "llm_calls"])
            writer.writeheader()
            writer.writerows(log_records)
        print(f"\nWrote execution log to {results_dir / 'eval_log.csv'}")


if __name__ == "__main__":
    main()
