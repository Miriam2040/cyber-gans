"""
Unified model client. Supports Google Gemini (free), Anthropic, and Groq.

Set ONE of these env vars:
  GOOGLE_API_KEY    → provider: google   (free tier: 1500 req/day)
  ANTHROPIC_API_KEY → provider: anthropic
  GROQ_API_KEY      → provider: groq     (free tier, fast)
"""

import os
import time
from typing import NamedTuple


class ModelResponse(NamedTuple):
    text: str
    tokens: int


_ENDPOINTS = {
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq":   "https://api.groq.com/openai/v1",
}

_ENV_KEYS = {
    "google":    "GOOGLE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq":      "GROQ_API_KEY",
}


def call(system: str, user: str, cfg: dict, max_tokens: int = 2048, json_mode: bool = False) -> ModelResponse:
    provider = cfg.get("provider", "google")
    model_name = cfg["models"][provider]

    if provider == "anthropic":
        return _call_anthropic(system, user, model_name, max_tokens)
    elif provider == "google":
        return _call_google_native(system, user, model_name, max_tokens, json_mode)
    else:
        return _call_openai_compat(system, user, model_name, provider, max_tokens, json_mode)


def _call_anthropic(system: str, user: str, model: str, max_tokens: int) -> ModelResponse:
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    resp = client.messages.create(
        model=model, max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return ModelResponse(
        text=resp.content[0].text,
        tokens=resp.usage.input_tokens + resp.usage.output_tokens,
    )


def _call_openai_compat(
    system: str, user: str, model: str, provider: str, max_tokens: int, json_mode: bool
) -> ModelResponse:
    from openai import OpenAI
    env_key = _ENV_KEYS[provider]
    api_key = os.environ.get(env_key, "")
    if not api_key:
        raise EnvironmentError(
            f"Missing env var {env_key}. "
            f"For Google: https://aistudio.google.com/  "
            f"For Groq: https://console.groq.com/"
        )
    kwargs = dict(api_key=api_key)
    if provider in _ENDPOINTS:
        kwargs["base_url"] = _ENDPOINTS[provider]

    client = OpenAI(**kwargs)
    kwargs2 = {}
    if json_mode:
        kwargs2["response_format"] = {"type": "json_object"}
    resp = client.chat.completions.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        **kwargs2,
    )
    tokens = resp.usage.total_tokens if resp.usage else 0
    return ModelResponse(text=resp.choices[0].message.content, tokens=tokens)


def _call_google_native(system: str, user: str, model: str, max_tokens: int, json_mode: bool) -> ModelResponse:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])
    cfg_obj = types.GenerateContentConfig(
        system_instruction=system,
        max_output_tokens=max_tokens,
        thinking_config=types.ThinkingConfig(thinking_budget=0),
        response_mime_type="application/json" if json_mode else None,
    )
    # Retry on transient 503/429 errors
    for attempt in range(4):
        try:
            resp = client.models.generate_content(model=model, contents=user, config=cfg_obj)
            break
        except Exception as e:
            msg = str(e)
            if attempt < 3 and ("503" in msg or "429" in msg or "UNAVAILABLE" in msg or "quota" in msg.lower()):
                wait = 15 * (2 ** attempt)
                print(f"  [API {attempt+1}/4] transient error, retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise
    tokens = resp.usage_metadata.total_token_count or 0 if resp.usage_metadata else 0
    text = resp.text or ""
    return ModelResponse(text=text, tokens=tokens)
