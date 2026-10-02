"""
test_component2.py — Manual verification script for Component 2 attack paths.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contracts import AttackType
from attack_engine.runner import run_attack


def verify_attack_paths():
    target_url = "http://test_chatbot:9000/chat"
    print("=== STARTING COMPONENT 2 ATTACK ENGINE PATH VERIFICATIONS ===")

    # 1. Verify Context Manipulation (PATH 1: Multi-turn)
    print("\n1. Running context_manipulation (PATH 1: Multi-turn)...")
    res_cm = run_attack(AttackType.context_manipulation, target_url)
    print(f"   Payload: {res_cm.payload[:100]}...")
    print(f"   Response: {res_cm.response[:100]}...")
    print(f"   Success status: {res_cm.success}")
    assert res_cm.payload.startswith("[Multi-turn]"), "FAILED: payload should start with [Multi-turn]"
    print("   ✅ PATH 1 Success!")

    # 2. Verify Prompt Injection (PATH 2: Adaptive Refinement)
    print("\n2. Running prompt_injection (PATH 2: Adaptive)...")
    res_pi = run_attack(AttackType.prompt_injection, target_url)
    print(f"   Payload: {res_pi.payload[:100]}...")
    print(f"   Response: {res_pi.response[:100]}...")
    print(f"   Success status: {res_pi.success}")
    assert "[Adaptive Iter" in res_pi.payload, "FAILED: payload should contain [Adaptive Iter"
    print("   ✅ PATH 2 Success!")

    # 3. Verify SQL Injection (PATH 3: Single-shot)
    print("\n3. Running sql_injection (PATH 3: Single-shot)...")
    res_sql = run_attack(AttackType.sql_injection, target_url)
    print(f"   Payload: {res_sql.payload}")
    print(f"   Response: {res_sql.response}")
    print(f"   Success status: {res_sql.success}")
    assert not res_sql.payload.startswith("[Multi-turn]"), "FAILED: single-shot should not start with [Multi-turn]"
    assert "[Adaptive" not in res_sql.payload, "FAILED: single-shot should not contain [Adaptive"
    print("   ✅ PATH 3 Success!")

    print("\n=== ALL ATTACK ENGINE PATHS VERIFIED SUCCESSFULLY ===")


if __name__ == "__main__":
    verify_attack_paths()
