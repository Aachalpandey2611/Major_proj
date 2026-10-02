import urllib.request
import json
import time
import redis
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contracts import AttackType
from attack_engine.runner import run_attack

# Use the docker service name inside the container network
CHATBOT_URL = "http://test_chatbot:9000"
REDIS_URL = "redis://redis:6379/0"

def test_force_failure():
    # 1. Enable secure mode on target chatbot (makes it refuse everything)
    print("Enabling SECURE_MODE on test_chatbot...")
    req_sec = urllib.request.Request(f"{CHATBOT_URL}/secure?enabled=true", method="POST")
    urllib.request.urlopen(req_sec)

    # 2. Setup Redis counter
    r = redis.from_url(REDIS_URL, decode_responses=True)
    scan_id = "test_adaptive_123"
    r.delete(f"llm_calls:{scan_id}")

    before_calls = r.get(f"llm_calls:{scan_id}") or "0"
    print(f"Redis llm_calls:{scan_id} before test = {before_calls}")

    # 3. Run prompt injection attack (which will fail iteration 1, 2, and 3 because target is secure)
    print("Running prompt_injection attack (expecting 3 iterations)...")
    result = run_attack(
        attack_type=AttackType.prompt_injection,
        target_url=f"{CHATBOT_URL}/chat",
        scan_id=scan_id
    )

    print("\n--- ATTACK FINAL RESULTS ---")
    print(f"Final Payload: {result.payload}")
    print(f"Final Response: {result.response}")
    print(f"Final Success: {result.success}")

    # 4. Check Redis counter after the run
    after_calls = r.get(f"llm_calls:{scan_id}") or "0"
    print(f"Redis llm_calls:{scan_id} after test = {after_calls}")

    # 5. Restore vulnerable mode
    print("Disabling SECURE_MODE back on test_chatbot...")
    req_vul = urllib.request.Request(f"{CHATBOT_URL}/secure?enabled=false", method="POST")
    urllib.request.urlopen(req_vul)

if __name__ == "__main__":
    test_force_failure()
