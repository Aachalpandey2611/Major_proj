import urllib.request
import json
import time
import redis

# Use docker network service names
CHATBOT_URL = "http://test_chatbot:9000"
BACKEND_API_URL = "http://backend:8000"
REDIS_URL = "redis://redis:6379/0"

def test():
    # 1. Ensure secure mode is disabled on target chatbot
    print("Disabling SECURE_MODE on test_chatbot...")
    req_vul = urllib.request.Request(f"{CHATBOT_URL}/secure?enabled=false", method="POST")
    urllib.request.urlopen(req_vul)

    # 2. Trigger scan
    print("Triggering scan on vulnerable chatbot...")
    req_scan = urllib.request.Request(f"{BACKEND_API_URL}/api/v1/scans/?target_id=8c4797fb-608d-4626-9e9e-d9300f17cb3c", method="POST")
    with urllib.request.urlopen(req_scan) as resp:
        scan = json.loads(resp.read().decode())
        scan_id = scan["scan_id"]
        print("Scan Triggered. ID:", scan_id)

    # 3. Poll for done status
    for i in range(15):
        time.sleep(2)
        with urllib.request.urlopen(f"{BACKEND_API_URL}/api/v1/scans/{scan_id}") as resp:
            data = json.loads(resp.read().decode())
            print(f"Poll {i+1} status: {data['status']}")
            if data["status"] in ("done", "failed"):
                break

    # 4. Check Redis llm_calls counter
    r = redis.from_url(REDIS_URL, decode_responses=True)
    calls = r.get(f"llm_calls:{scan_id}") or "0"
    print(f"Redis llm_calls:{scan_id} count = {calls}")

if __name__ == "__main__":
    test()
