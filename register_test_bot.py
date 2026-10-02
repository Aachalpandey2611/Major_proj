#!/usr/bin/env python3
"""
Quick script to register the test chatbot and verify ownership
"""
import requests
import os
import sys

BACKEND_URL = "http://localhost:8001/api/v1"
CHATBOT_URL = "http://test_chatbot:9000"

def register_and_verify():
    print("=" * 60)
    print("  Registering Test Chatbot with SentinelLoop")
    print("=" * 60)
    print()
    
    # Step 1: Register the target
    print(f"📝 Step 1: Registering target: {CHATBOT_URL}")
    try:
        response = requests.post(
            f"{BACKEND_URL}/targets/",
            params={
                "name": "Test Chatbot (Vulnerable)",
                "url": CHATBOT_URL,
                "environment": "dev"
            }
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return False
    
    target_id = data["id"]
    verification_token = data["verification_token"]
    management_token = data.get("management_token")
    
    print(f"✅ Target registered!")
    print(f"   Target ID: {target_id}")
    print(f"   Verification Token: {verification_token}")
    if management_token:
        print(f"   Management Token: {management_token[:20]}...")
    print()
    
    # Step 2: Create verification file
    print("📝 Step 2: Creating verification file...")
    verification_content = f"sentinel-verify={verification_token}"
    well_known_dir = os.path.join(os.path.dirname(__file__), "test_chatbot", ".well-known")
    os.makedirs(well_known_dir, exist_ok=True)
    
    verification_file = os.path.join(well_known_dir, "sentinelloop-verify.txt")
    with open(verification_file, "w", encoding="utf-8") as f:
        f.write(verification_content)
    
    print(f"✅ Verification file created at: {verification_file}")
    print(f"   Content: {verification_content}")
    print()
    
    # Step 3: Verify ownership
    print("📝 Step 3: Verifying ownership...")
    try:
        response = requests.get(f"{BACKEND_URL}/targets/{target_id}/verify")
        response.raise_for_status()
        result = response.json()
        print(f"✅ {result['message']}")
    except requests.exceptions.HTTPError as e:
        print(f"❌ Verification failed: {e}")
        print(f"   Response: {e.response.text}")
        return False
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False
    
    print()
    print("=" * 60)
    print("  🎉 SUCCESS! Test chatbot is ready for scanning")
    print("=" * 60)
    print()
    print(f"Target ID: {target_id}")
    print(f"Next step: Go to http://localhost:5173 and launch a scan!")
    print()
    
    return True

if __name__ == "__main__":
    success = register_and_verify()
    sys.exit(0 if success else 1)
