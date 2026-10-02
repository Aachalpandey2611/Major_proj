"""
multi_turn_sender.py — Sends multi-turn conversation payloads to the target.
"""

from typing import Dict, List
import json
import httpx


def send_multi_turn(
    url: str,
    turns: List[str],
    auth_token: str = None,
    timeout: int = 30,
) -> List[Dict[str, str]]:
    """
    Send a multi-turn conversation history to the target URL.

    Args:
        url: Target endpoint.
        turns: List of user prompt strings in sequence.
        auth_token: Plaintext authorization token (if any).
        timeout: Request timeout in seconds.

    Returns:
        A list of dicts: [{"prompt": prompt, "response": response}, ...]
    """
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    history: List[Dict[str, str]] = []
    results: List[Dict[str, str]] = []

    for turn_prompt in turns:
        # Append current user turn to the conversation history
        history.append({"role": "user", "content": turn_prompt})

        body = {
            "messages": history,
            "max_tokens": 500
        }
        print(f"[Multi-Turn Debug] Turn {len(results)+1} request messages sent: {history}")

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, headers=headers, json=body)
                
                # If the schema fails or returns non-200, try sending with a minimal body containing the latest message
                if resp.status_code != 200:
                    resp = client.post(url, headers=headers, json={"message": turn_prompt})

                if resp.status_code != 200:
                    content = f"[ERROR: HTTP {resp.status_code}]"
                else:
                    try:
                        data = resp.json()
                        # Parse response trying, in order:
                        choices = data.get("choices")
                        if choices and isinstance(choices, list) and len(choices) > 0:
                            val = choices[0].get("message", {}).get("content")
                            content = str(val).strip() if val is not None else json.dumps(data)
                        else:
                            content = None
                            for key in ["response", "message", "text"]:
                                val = data.get(key)
                                if val is not None:
                                    content = str(val).strip()
                                    break
                            if content is None:
                                content = json.dumps(data)
                    except ValueError:
                        content = resp.text.strip()
        except httpx.TimeoutException:
            content = "[ERROR: Request timed out]"
        except Exception as e:
            content = f"[ERROR: {e}]"

        results.append({"prompt": turn_prompt, "response": content})
        history.append({"role": "assistant", "content": content})

    return results
