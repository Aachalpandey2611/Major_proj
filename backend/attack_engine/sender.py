"""
sender.py — Sends a single-turn payload to the target chatbot URL.
"""

import json
import httpx


def send_to_target(url: str, payload: str, auth_token: str = None, timeout: int = 5) -> str:
    """
    Send a single-turn message payload to the target URL.

    Args:
        url: The absolute target URL.
        payload: The prompt text/attack payload.
        auth_token: Plaintext authorization token (if any).
        timeout: Request timeout in seconds.

    Returns:
        The response content string from the chatbot, or an error message.
    """
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # Auto-detect API endpoint if base URL is provided
    # Try common endpoint paths in priority order
    base_url = url.rstrip('/')  # Remove trailing slash if present
    endpoints_to_try = [
        (f"{base_url}/api/chat", {"message": payload}),  # Most common pattern
        (f"{base_url}/chat", {"message": payload}),
        (f"{base_url}/v1/chat/completions", {"messages": [{"role": "user", "content": payload}], "max_tokens": 500}),
        (f"{base_url}", {"message": payload}),  # Try root without slash
    ]

    def try_post(target_url, body):
        """Try a single POST request. Returns (success: bool, result: str)"""
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(target_url, headers=headers, json=body)
                
                # Only accept 200 as success
                if resp.status_code != 200:
                    return False, f"[ERROR: HTTP {resp.status_code}]"
                
                # Try to parse JSON response
                try:
                    data = resp.json()
                except ValueError:
                    # Not JSON, return as plain text
                    return True, resp.text.strip()

                # Parse structured JSON responses
                # Try OpenAI format first
                choices = data.get("choices")
                if choices and isinstance(choices, list) and len(choices) > 0:
                    content = choices[0].get("message", {}).get("content")
                    if content is not None:
                        return True, str(content).strip()

                # Try common response keys
                for key in ["response", "message", "text", "answer", "reply"]:
                    val = data.get(key)
                    if val is not None:
                        return True, str(val).strip()

                # If no known key found, return entire JSON
                return True, json.dumps(data)
                
        except httpx.TimeoutException:
            return False, "[ERROR: Request timed out]"
        except httpx.ConnectError:
            return False, "[ERROR: Connection refused]"
        except Exception as e:
            return False, f"[ERROR: {type(e).__name__}]"

    # Try all endpoint + body combinations
    last_error = "[ERROR: No endpoint responded successfully]"
    for endpoint_url, body in endpoints_to_try:
        success, result = try_post(endpoint_url, body)
        if success:
            return result
        # Store last error for debugging
        last_error = result

    # All attempts failed
    return last_error
