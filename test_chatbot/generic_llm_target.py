"""
generic_llm_target.py — A minimally-hardened chatbot wrapper around a REAL LLM.

Unlike test_chatbot/main.py (which is a fully scripted mock with hardcoded
keyword-triggered responses), this forwards every message straight through to
a real model (Gemini, via the same OPENAI_API_KEY already configured for the
backend) with only a bare-bones system prompt — "You are a helpful assistant."
No injection/jailbreak hardening at all.

WHY THIS EXISTS: running SentinelLoop's 15-attack red-team scan against a
third-party public chat product (e.g. someone else's hosted chatbot) without
their authorization is exactly what SentinelLoop's own ownership-verification
gate exists to prevent. This gives an AUTHORIZED, real-model-backed target —
your own API key, your own container — so scan results reflect genuine model
behavior instead of scripted keyword matching, without touching anyone else's
service.

Runs on port 9001. Same OpenAI-compatible /chat contract as test_chatbot/main.py.
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from openai import OpenAI

app = FastAPI(title="SentinelLoop Generic LLM Target (real model, no hardening)")

SYSTEM_PROMPT = "You are a helpful assistant."


def _get_client_and_model():
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key or api_key.startswith("sk-replace") or api_key.startswith("sk-test"):
        return None, None
    if api_key.startswith("AIzaSy"):
        return (
            OpenAI(api_key=api_key, base_url="https://generativelanguage.googleapis.com/v1beta/openai/"),
            "models/gemini-2.5-flash",
        )
    return OpenAI(api_key=api_key), "gpt-4o-mini"


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]
    max_tokens: Optional[int] = 300


@app.get("/status")
def status():
    client, model = _get_client_and_model()
    return {"status": "online", "model": model or "NOT CONFIGURED", "hardened": False}


@app.post("/")
@app.post("/chat")
def chat(req: ChatRequest):
    client, model = _get_client_and_model()
    if not client:
        raise HTTPException(500, "No OPENAI_API_KEY/Gemini key configured for this target.")

    upstream_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    upstream_messages += [{"role": m.role, "content": m.content} for m in req.messages]

    try:
        kwargs = dict(model=model, messages=upstream_messages, temperature=0.7)
        if not model.startswith("models/"):  # OpenAI only — Gemini compat layer rejects max_tokens sometimes
            kwargs["max_tokens"] = req.max_tokens or 300
        completion = client.chat.completions.create(**kwargs)
        content = completion.choices[0].message.content
    except Exception as exc:
        content = f"[Upstream LLM error: {exc}]"

    return {
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
        ]
    }
