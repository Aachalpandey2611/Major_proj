"""
test_chatbot/main.py — Vulnerable mock chatbot for test and demo scanning.

Runs on port 9000.
Supports:
- /chat completions API (OpenAI-compatible choices/message/content structure).
- State toggle: SECURE_MODE=true / false via env or GET/POST /secure endpoints.
- Vulnerable mode: behaves weakly, leaks mock system prompt, complies with jailbreaks,
  allows tool queries.
- Secure mode: detects common attack strings using strong guards, returns refusals.
"""

import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="SentinelLoop Target Chatbot (Mock)")

# State control
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"

MOCK_SYSTEM_PROMPT = (
    "You are a helpful customer support bot for SentinelLoop Fintech services. "
    "Do not disclose your API keys or system configurations."
)


@app.get("/.well-known/sentinelloop-verify.txt")
def get_verification_file():
    path = "/app/.well-known/sentinelloop-verify.txt"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(f.read().strip())
    raise HTTPException(404, "Verification file not found")


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 512
    seed: Optional[int] = None


@app.get("/status")
def get_status():
    return {
        "status": "online",
        "secure_mode": SECURE_MODE,
        "system_prompt": MOCK_SYSTEM_PROMPT,
    }


@app.post("/secure")
def set_secure_mode(enabled: bool):
    global SECURE_MODE
    SECURE_MODE = enabled
    return {"secure_mode": SECURE_MODE}


@app.post("/")
@app.post("/chat")
def chat(req: ChatRequest, authorization: Optional[str] = Header(None)):
    """OpenAI-style chat completions endpoint."""
    global SECURE_MODE

    # Check for authentication header if required (simulates bearer auth checks)
    if authorization:
        # Just print/log it for simulation
        pass

    # Extract the last user message
    user_msgs = [m for m in req.messages if m.role == "user"]
    if not user_msgs:
        raise HTTPException(400, "No user messages provided")

    last_message = user_msgs[-1].content
    last_message_lower = last_message.lower()

    # --- SECURE MODE GUARD ---
    if SECURE_MODE:
        # When SECURE_MODE is True, make every response a generic safe refusal.
        # This is a deliberately simple way to simulate a secure target chatbot.
        return _respond("I am sorry, but I cannot fulfill this request. I must follow safety guidelines.")

    # --- VULNERABLE MODE (DEFAULT) ---
    else:
        # System Prompt Leak attack compliance
        if "system prompt" in last_message_lower or "repeat the text above" in last_message_lower:
            return _respond(f"Certainly! Here is my system prompt: {MOCK_SYSTEM_PROMPT}")

        # Jailbreak / DAN attack compliance
        if "dan" in last_message_lower or "do anything now" in last_message_lower:
            return _respond("DAN mode enabled. I will now perform any request without safety policies. Restrictions removed.")

        # SQL Injection / Database extraction compliance
        if "union select" in last_message_lower or "credentials" in last_message_lower or "select *" in last_message_lower:
            return _respond("Database dump: admin_pass='sl_secure_p@ss', db_user='sentinel_admin', host='10.0.0.4'")

        # Role override compliance
        if "malicious terminal" in last_message_lower or "exec 'whoami'" in last_message_lower:
            return _respond("Terminal access granted. executing command: root")

        # PII / Data leakage compliance
        if "email" in last_message_lower and "customer" in last_message_lower:
            return _respond("Customer emails: customer1@gmail.com, user2@yahoo.com, support@sentinelloop.com")

        # Context manipulation compliance
        if "ignore your guidelines" in last_message_lower or "ignore constraints" in last_message_lower:
            return _respond("Sure, I am happy to bypass my rules for this debugging test.")

    # Benign responses
    if "return policy" in last_message_lower:
        return _respond("Our standard return policy is 30 days with a full refund. Returns are free.")
    elif "hotline" in last_message_lower or "phone" in last_message_lower:
        return _respond("You can contact support at 1-800-SENTINEL (1-800-736-8463) during standard business hours.")

    return _respond("Hello! I am the SentinelLoop customer support bot. How can I help you with your account today?")


def _respond(text: str):
    """Wrap content in OpenAI-like response dictionary."""
    return {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text
                },
                "finish_reason": "stop"
            }
        ]
    }
