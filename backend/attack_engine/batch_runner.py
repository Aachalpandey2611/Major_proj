"""
batch_runner.py — Aggregate red-team evaluation report.

The scanner in runner.py/scan_tasks.py runs ONE representative prompt per
attack category per scan (fast, good for the CI gate). This module runs EVERY
prompt in each category's dataset file against a target and tallies results —
"92/100 prompt-injection attempts were correctly defended", not just pass/fail
on a single probe. Built for authorized batch red-teaming of a target you
control (see test_chatbot/generic_llm_target.py for a real-model-backed
target you can legally point this at).
"""

import json
import os
from typing import Optional

from attack_engine.sender import send_to_target
from attack_engine.multi_turn_sender import send_multi_turn
from contracts import AttackType
from detection_engine.detector import detect
from fix_engine.fix_mappings import FIX_MAPPINGS

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset")

# Attack types with only a couple of hand-authored prompts + heavy multi-turn
# entries are excluded from the bulk numeric sweep by default (multi-turn
# conversations are expensive to sample in bulk) — batch mode covers the
# 13 single-turn-dominant categories; context_manipulation/tool_abuse are
# still included but only their single-turn entries are sampled here.
CATEGORY_ORDER = [
    AttackType.prompt_injection,
    AttackType.jailbreak,
    AttackType.system_prompt_leak,
    AttackType.data_leakage,
    AttackType.role_override,
    AttackType.indirect_injection,
    AttackType.rag_poisoning,
    AttackType.sql_injection,
    AttackType.api_abuse,
    AttackType.denial_of_wallet,
    AttackType.training_data_extraction,
    AttackType.sponge_attack,
    AttackType.few_shot_leakage,
    AttackType.context_manipulation,
    AttackType.tool_abuse,
]

FILE_MAP = {
    AttackType.prompt_injection: "prompt_injection.json",
    AttackType.jailbreak: "jailbreak.json",
    AttackType.system_prompt_leak: "system_prompt_leak.json",
    AttackType.indirect_injection: "indirect_injection.json",
    AttackType.data_leakage: "data_leakage.json",
    AttackType.role_override: "role_override.json",
    AttackType.context_manipulation: "context_manipulation.json",
    AttackType.rag_poisoning: "rag_poisoning.json",
    AttackType.tool_abuse: "tool_abuse.json",
    AttackType.denial_of_wallet: "denial_of_wallet.json",
    AttackType.training_data_extraction: "training_data_extraction.json",
    AttackType.sponge_attack: "sponge_attack.json",
    AttackType.sql_injection: "sql_injection.json",
    AttackType.api_abuse: "api_abuse.json",
    AttackType.few_shot_leakage: "few_shot_leakage.json",
}


def _load_prompts(attack_type: AttackType, sample_size: int):
    path = os.path.join(DATASET_DIR, FILE_MAP[attack_type])
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    single_turn = [e for e in entries if "prompt" in e and e["prompt"]]
    multi_turn = [e for e in entries if "turns" in e and e["turns"]]

    sampled = single_turn[:sample_size]
    remaining = sample_size - len(sampled)
    if remaining > 0:
        sampled += multi_turn[:remaining]
    return sampled


def run_batch_report(
    target_url: str,
    auth_token: Optional[str] = None,
    sample_size: int = 10,
    categories: Optional[list] = None,
    progress_cb=None,
) -> dict:
    """
    Run up to `sample_size` prompts per attack category against target_url and
    tally results.

    Returns a report dict shaped for direct display:
        {
          "target": target_url,
          "total_tests": int,
          "categories": [
            {"attack_type": str, "tests_run": int, "defended": int,
             "bypassed": int, "detection_rate": float}, ...
          ],
          "overall_detection_rate": float,
          "severity_breakdown": {"critical": int, "high": int, "medium": int,
                                  "low": int, "passed": int},
          "vulnerabilities": [ {attack_type, severity, payload, response}, ... ]
        }
    """
    active_categories = categories or CATEGORY_ORDER

    category_results = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vulnerabilities = []
    total_tests = 0
    total_defended = 0

    for attack_type in active_categories:
        prompts = _load_prompts(attack_type, sample_size)
        defended = 0
        bypassed = 0

        for entry in prompts:
            if "turns" in entry:
                results = send_multi_turn(url=target_url, turns=entry["turns"], auth_token=auth_token)
                payload = " -> ".join(r["prompt"][:40] for r in results) if results else ""
                response = results[-1]["response"] if results else ""
            else:
                payload = entry["prompt"]
                response = send_to_target(url=target_url, payload=payload, auth_token=auth_token)

            detection = detect(attack_type=attack_type, payload=payload, response=response, scan_id=None)

            if detection["success"]:
                bypassed += 1
                mapping = FIX_MAPPINGS.get(attack_type, {})
                sev = mapping.get("severity")
                sev_key = sev.value if sev else "medium"
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1
                vulnerabilities.append({
                    "attack_type": attack_type.value,
                    "severity": sev_key,
                    "payload": payload,
                    "response": response[:300],
                })
            else:
                defended += 1

            if progress_cb:
                progress_cb(attack_type.value, len(prompts))

        tests_run = defended + bypassed
        total_tests += tests_run
        total_defended += defended

        category_results.append({
            "attack_type": attack_type.value,
            "tests_run": tests_run,
            "defended": defended,
            "bypassed": bypassed,
            "detection_rate": round(100 * defended / tests_run, 1) if tests_run else 0.0,
        })

    overall_rate = round(100 * total_defended / total_tests, 1) if total_tests else 0.0

    return {
        "target": target_url,
        "total_tests": total_tests,
        "categories": category_results,
        "overall_detection_rate": overall_rate,
        "severity_breakdown": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "passed": total_defended,
        },
        "vulnerabilities": vulnerabilities,
    }
