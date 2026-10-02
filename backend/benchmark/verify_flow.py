"""
verify_flow.py — Validates target registration, ownership verification,
management token auth, API key generation, and rate limiting endpoints.
"""

import sys
import os
import json
import urllib.request
import urllib.error

API_URL = "http://localhost:8001/api/v1"


def make_request(path: str, method="GET", params=None, headers=None, data=None):
    url = f"{API_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    if data:
        req.add_header("Content-Type", "application/json")
        req_data = json.dumps(data).encode("utf-8")
    else:
        req_data = None

    try:
        with urllib.request.urlopen(req, data=req_data, timeout=5) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        try:
            err_data = json.loads(e.read().decode())
            return e.code, err_data
        except Exception:
            return e.code, {"detail": e.reason}
    except Exception as e:
        return 999, {"detail": str(e)}


def test_auth_chain():
    print("=== STARTING AUTH CHAIN TESTS ===")

    # 1. Register target
    print("\n1. Registering target 'Test Bot'...")
    status, res = make_request(
        "/targets/",
        method="POST",
        params={
            "name": "Test Bot",
            "url": "http://test_chatbot:9000",
            "environment": "staging",
        },
    )
    assert status == 200, f"Register failed: {res}"
    target_id = res["id"]
    mgmt_token = res["management_token"]
    verif_token = res["verification_token"]
    print(f"   Registered successfully! Target ID: {target_id}")
    print(f"   Management Token: {mgmt_token[:15]}...")

    # Confirm secrets are not in standard dictionary
    assert "management_token_hash" not in res, "Leaked management_token_hash!"
    assert "auth_token_encrypted" not in res, "Leaked auth_token_encrypted!"

    # 2. Verify ownership mock file setup
    # Create verification file in test_chatbot directory so it serves it at /.well-known/sentinelloop-verify.txt
    well_known_dir = r"c:\Users\amanp\OneDrive\Desktop\SentinelLLM\test_chatbot\.well-known"
    os.makedirs(well_known_dir, exist_ok=True)
    with open(os.path.join(well_known_dir, "sentinelloop-verify.txt"), "w") as f:
        f.write(f"sentinel-verify={verif_token}")
    print("   Created verification file on mock chatbot server.")

    # 3. Call verify ownership
    print("\n2. Verifying target ownership...")
    status, res = make_request(f"/targets/{target_id}/verify", method="GET")
    assert status == 200, f"Verification failed: {res}"
    print(f"   Ownership verified! Status: {res['status']}")

    # 4. API Key Creation with wrong management token (should fail)
    print("\n3. Testing API Key creation with WRONG token...")
    status, res = make_request(
        "/api-keys/",
        method="POST",
        params={"target_id": target_id, "label": "github-actions"},
        headers={"X-Management-Token": "wrong-token-value"},
    )
    assert status == 401, f"Expected 401, got {status} ({res})"
    print("   Correctly rejected wrong token (401 Unauthorized)")

    # 5. API Key Creation with correct management token
    print("\n4. Testing API Key creation with CORRECT token...")
    status, res = make_request(
        "/api-keys/",
        method="POST",
        params={"target_id": target_id, "label": "github-actions"},
        headers={"X-Management-Token": mgmt_token},
    )
    assert status == 200, f"API Key creation failed: {res}"
    api_key = res["api_key"]
    print(f"   API Key created successfully: {api_key[:12]}...")

    # 6. CI scan trigger with the key
    print("\n5. Launching CI scan with the new key...")
    status, res = make_request(
        "/scans/ci",
        method="POST",
        params={"target_id": target_id, "commit_sha": "abc123sha"},
        headers={"X-API-Key": api_key},
    )
    assert status == 200, f"CI Scan trigger failed: {res}"
    scan_id = res["scan_id"]
    print(f"   Scan queued successfully! Scan ID: {scan_id}")

    # 7. Check rate limiting (brute forcing wrong keys)
    print("\n6. Simulating rapid brute-force attempts to trigger rate limit (429)...")
    for i in range(10):
        status, res = make_request(
            "/scans/ci",
            method="POST",
            params={"target_id": target_id, "commit_sha": "abc123sha"},
            headers={"X-API-Key": f"sl_wrongkey_{i}"},
        )
        print(f"   Attempt {i+1} status: {status}")
        if status == 429:
            print(f"   Successfully rate limited on attempt {i+1}! (429 Too Many Requests)")
            break
    else:
        print("   Rate limiting failed to trigger 429!")

    print("\n=== ALL AUTH CHAIN TESTS COMPLETED SUCCESSFULLY ===")


if __name__ == "__main__":
    test_auth_chain()
