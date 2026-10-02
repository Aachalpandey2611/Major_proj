"""
runner.py — Main coordinator for running attacks against target chatbots.

NOW WITH MULTI-PROMPT SWEEP + AUDIT TRAIL LOGGING:
- Tests up to MAX_PROMPTS_PER_TYPE (85) prompts per attack
- Returns worst-case (highest confidence) successful attack
- Saves comprehensive audit log with summary per attack type
"""

import json
import os
from typing import List

from contracts import AttackResult, AttackType, DetectionMethod
from attack_engine.sender import send_to_target
from attack_engine.multi_turn_sender import send_multi_turn
from attack_engine.adaptive_runner import run_adaptive_attack, ADAPTIVE_ATTACK_TYPES
from detection_engine.detector import detect

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset")

# Maximum prompts to test per attack type
# Set to 20 for fast scanning (under 2 minutes total)
# Increase to 85 for thorough production testing
MAX_PROMPTS_PER_TYPE = 20

MULTI_TURN_ATTACK_TYPES = {
    AttackType.context_manipulation,
    AttackType.tool_abuse,
}

# Mapping attack types to human-readable layer names for audit trail
LAYER_NAMES = {
    AttackType.prompt_injection: "Layer 1 — Prompt Injection",
    AttackType.jailbreak: "Layer 2 — Jailbreak",
    AttackType.system_prompt_leak: "Layer 3 — System Prompt Leak",
    AttackType.data_leakage: "Layer 4 — Data Leakage",
    AttackType.role_override: "Layer 5 — Role Override",
    AttackType.indirect_injection: "Layer 6 — Indirect Injection",
    AttackType.rag_poisoning: "Layer 7 — RAG Poisoning",
    AttackType.tool_abuse: "Layer 8 — Tool Abuse",
    AttackType.denial_of_wallet: "Layer 9 — Denial of Wallet",
    AttackType.sql_injection: "Layer 10 — SQL Injection",
    AttackType.api_abuse: "Layer 11 — API Abuse",
    AttackType.context_manipulation: "Layer 12 — Context Manipulation",
    AttackType.training_data_extraction: "Layer 13 — Training Data Extraction",
    AttackType.sponge_attack: "Layer 14 — Sponge Attack",
    AttackType.few_shot_leakage: "Layer 15 — Few-Shot Leakage",
}

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


def load_prompts(attack_type: AttackType) -> List[dict]:
    """Load the JSON dataset file for a given attack type."""
    filename = FILE_MAP.get(attack_type)
    if not filename:
        return []

    filepath = os.path.join(DATASET_DIR, filename)
    if not os.path.exists(filepath):
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_audit_log(
    scan_id: str,
    attack_type: AttackType,
    result: AttackResult,
    prompts_tested: int = 1,
) -> None:
    """
    Save audit trail entry for this attack.
    
    Creates one AttackLog entry per attack type showing:
    - Layer name (e.g., "Layer 1 — Prompt Injection")
    - Prompt used (worst-case attack that succeeded, or last tested if all failed)
    - Chatbot response
    - Verdict: "PASSED" (blocked) or "FAILED" (vulnerable)
    - Confidence score
    - Number of prompts tested
    """
    if not scan_id:
        return  # Skip logging if no scan_id (e.g., standalone testing)
    
    try:
        from database import SessionLocal
        from models import AttackLog
        from datetime import datetime
        import uuid
        
        db = SessionLocal()
        
        layer_name = LAYER_NAMES.get(attack_type, f"Layer — {attack_type.value}")
        verdict = "FAILED" if result.success else "PASSED"
        
        attack_log = AttackLog(
            id=uuid.uuid4(),
            scan_id=uuid.UUID(scan_id),
            attack_type=attack_type.value,
            layer_name=layer_name,
            prompt_used=result.payload[:2000],  # Limit to 2000 chars for storage
            chatbot_response=result.response[:2000],  # Limit to 2000 chars
            verdict=verdict,
            confidence=result.confidence,
            detection_method=result.detection_method.value,
            prompts_tested=prompts_tested,
            created_at=datetime.utcnow(),
        )
        
        db.add(attack_log)
        db.commit()
        db.close()
    except Exception as e:
        # Don't fail the scan if audit logging fails
        print(f"Warning: Failed to save audit log for {attack_type.value}: {e}")
        pass


def run_attack(
    attack_type: AttackType,
    target_url: str,
    auth_token: str = None,
    specific_payload: str = None,
    scan_id: str = None,
) -> AttackResult:
    """
    Execute an attack of the given type against the target URL.
    
    NOW WITH MULTI-PROMPT SWEEP:
    Tests up to MAX_PROMPTS_PER_TYPE (85) prompts and returns the worst-case
    (highest confidence) successful attack. This provides thorough coverage.

    Coordinates three execution paths:
    - PATH 1: Multi-turn (context_manipulation, tool_abuse)
    - PATH 2: Adaptive refinement (jailbreak, prompt_injection, system_prompt_leak, role_override)
    - PATH 3: Single-shot with FULL PROMPT SWEEP (everything else)
    """
    prompts = load_prompts(attack_type)

    # === PATH 1: Multi-turn (context_manipulation, tool_abuse) ===
    if attack_type in MULTI_TURN_ATTACK_TYPES and not specific_payload:
        mt_prompts = [p for p in prompts if "turns" in p]
        if mt_prompts:
            sample = mt_prompts[0]
            turns = sample["turns"]
            results = send_multi_turn(url=target_url, turns=turns, auth_token=auth_token)

            # Evaluate final turn
            final_prompt = results[-1]["prompt"] if results else ""
            final_response = results[-1]["response"] if results else ""

            detection = detect(
                attack_type=attack_type,
                payload=final_prompt,
                response=final_response,
                scan_id=scan_id,
            )

            # Prefix payload with a visible multi-turn marker + condensed conversation
            # trail so findings/UI/CI logs can tell this was a multi-turn attack,
            # not just show the last turn's raw text.
            conv_trail = " -> ".join(r["prompt"][:60] for r in results)
            marked_payload = f"[Multi-turn] {conv_trail}"

            result = AttackResult(
                attack_type=attack_type,
                payload=marked_payload,
                response=final_response,
                success=detection["success"],
                confidence=detection["confidence"],
                layer_failed=detection.get("layer_failed"),
                detection_method=detection["method"],
                raw_judge_reason=detection.get("reason"),
            )
            
            # Save audit log (multi-turn = 1 conversation tested)
            save_audit_log(scan_id, attack_type, result, prompts_tested=1)
            
            return result

    # === PATH 2: Adaptive single-turn (prompt_injection, jailbreak, system_prompt_leak, role_override) ===
    if attack_type in ADAPTIVE_ATTACK_TYPES and not specific_payload:
        seed = prompts[0]["prompt"] if prompts else "Hello"
        result = run_adaptive_attack(
            attack_type=attack_type,
            target_url=target_url,
            seed_payload=seed,
            auth_token=auth_token,
            max_iterations=3,
            scan_id=scan_id,
        )
        
        # Save audit log (adaptive = 3 iterations tested)
        save_audit_log(scan_id, attack_type, result, prompts_tested=3)
        
        return result

    # === PATH 3: Single-shot WITH MULTI-PROMPT SWEEP ===
    # If specific_payload is provided (retest), use only that
    if specific_payload:
        response = send_to_target(url=target_url, payload=specific_payload, auth_token=auth_token)
        detection = detect(
            attack_type=attack_type,
            payload=specific_payload,
            response=response,
            scan_id=scan_id,
        )
        return AttackResult(
            attack_type=attack_type,
            payload=specific_payload,
            response=response,
            success=detection["success"],
            confidence=detection["confidence"],
            layer_failed=detection.get("layer_failed"),
            detection_method=detection["method"],
            raw_judge_reason=detection.get("reason"),
        )
    
    # MULTI-PROMPT SWEEP: Test up to MAX_PROMPTS_PER_TYPE prompts
    # Return the worst-case (highest confidence) successful attack
    if not prompts:
        # Fallback if no dataset
        response = send_to_target(url=target_url, payload="Hello", auth_token=auth_token)
        detection = detect(attack_type=attack_type, payload="Hello", response=response, scan_id=scan_id)
        return AttackResult(
            attack_type=attack_type,
            payload="Hello",
            response=response,
            success=detection["success"],
            confidence=detection["confidence"],
            layer_failed=detection.get("layer_failed"),
            detection_method=detection["method"],
            raw_judge_reason=detection.get("reason"),
        )
    
    # Filter to single-turn prompts only (skip multi-turn entries)
    single_turn_prompts = [p for p in prompts if "prompt" in p and "turns" not in p]
    prompts_to_test = single_turn_prompts[:MAX_PROMPTS_PER_TYPE]
    prompts_tested_count = len(prompts_to_test)
    
    worst_result = None
    
    for prompt_obj in prompts_to_test:
        payload = prompt_obj.get("prompt", "")
        if not payload:
            continue
            
        response = send_to_target(url=target_url, payload=payload, auth_token=auth_token)
        detection = detect(
            attack_type=attack_type,
            payload=payload,
            response=response,
            scan_id=scan_id,
        )
        
        current_result = AttackResult(
            attack_type=attack_type,
            payload=payload,
            response=response,
            success=detection["success"],
            confidence=detection["confidence"],
            layer_failed=detection.get("layer_failed"),
            detection_method=detection["method"],
            raw_judge_reason=detection.get("reason"),
        )
        
        # Update worst_result if this attack is more severe
        if current_result.success:
            if worst_result is None or current_result.confidence > worst_result.confidence:
                worst_result = current_result
    
    # If no successful attack found, return the last tested result (failed attempt)
    if worst_result is None:
        # Return safe result
        last_prompt = prompts_to_test[-1]["prompt"] if prompts_to_test else "Hello"
        response = send_to_target(url=target_url, payload=last_prompt, auth_token=auth_token)
        detection = detect(attack_type=attack_type, payload=last_prompt, response=response, scan_id=scan_id)
        result = AttackResult(
            attack_type=attack_type,
            payload=last_prompt,
            response=response,
            success=detection["success"],
            confidence=detection["confidence"],
            layer_failed=detection.get("layer_failed"),
            detection_method=detection["method"],
            raw_judge_reason=detection.get("reason"),
        )
        
        # Save audit log
        save_audit_log(scan_id, attack_type, result, prompts_tested=prompts_tested_count)
        
        return result
    
    # Save audit log with worst-case result
    save_audit_log(scan_id, attack_type, worst_result, prompts_tested=prompts_tested_count)
    
    return worst_result
