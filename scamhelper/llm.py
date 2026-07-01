"""LLM client wrapper with caching, retry logic, error handling, and mock support.

Supports:
- Gemini API (via google-genai SDK or direct REST with rate-limit backoff)
- Mock client for offline, deterministic unit testing and evaluation
- Disk caching in .cache/llm/ keyed by SHA-256 of the prompt
- Structured JSON parsing with automatic markdown fence stripping
- Graceful degradation: missing API key returns a clear status instead of crashing
"""

import os
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# Cache directory
CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache" / "llm"


class LLMError(Exception):
    """Base exception for LLM operations."""
    pass


class MissingAPIKeyError(LLMError):
    """Raised when an API key is required but missing."""
    pass


class RateLimitError(LLMError):
    """Raised when hitting rate limits."""
    pass


class LLMTimeoutError(LLMError):
    """Raised on connection or read timeouts."""
    pass


class MalformedResponseError(LLMError):
    """Raised when the LLM returns invalid JSON or unparseable output."""
    pass


class BaseLLMClient:
    """Abstract base LLM client."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        raise NotImplementedError

    def is_available(self) -> bool:
        return True


class MockLLMClient(BaseLLMClient):
    """Mock LLM client for deterministic testing without network calls."""

    def __init__(self, model_name: str = "mock-model", responses: Optional[List[str]] = None):
        super().__init__(model_name)
        self.responses: List[str] = responses or []
        self.history: List[Dict[str, Any]] = []
        self.response_generator: Optional[Callable[[str, Optional[str]], str]] = None

    def add_response(self, resp: str):
        self.responses.append(resp)

    def set_generator(self, gen_fn: Callable[[str, Optional[str]], str]):
        self.response_generator = gen_fn

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        self.history.append({"prompt": prompt, "system_prompt": system_prompt})
        if self.response_generator:
            return self.response_generator(prompt, system_prompt)
        if self.responses:
            return self.responses.pop(0)
        return json.dumps({
            "action": "final",
            "verdict": "LOOKS LEGITIMATE",
            "scam_type": None,
            "red_flags": [],
            "steps": ["No scam signs detected."],
            "urgent": False,
            "uncertainty": "low"
        })

    def is_available(self) -> bool:
        return True


class GeminiLLMClient(BaseLLMClient):
    """Client for Google Gemini models via official SDK or REST API with backoff."""

    def __init__(self, model_name: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(model_name or os.getenv("LLM_MODEL", "gemini-3.1-flash-lite"))
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.last_api_latency: float = 0.0

    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key.strip() and not self.api_key.startswith("your_"))

    def discover_model(self) -> str:
        """Query Gemini API to list available models and select an active Flash-type model."""
        if not self.is_available():
            raise MissingAPIKeyError("Cannot discover models: GEMINI_API_KEY is not set.")

        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                models = data.get("models", [])
                flash_models = [
                    m["name"].replace("models/", "")
                    for m in models
                    if "generateContent" in m.get("supportedGenerationMethods", [])
                    and "flash" in m.get("name", "").lower()
                ]
                # Priority: flash-lite models first (higher free tier quotas)
                for pref in ["gemini-3.1-flash-lite", "gemini-3.1-flash-lite-preview", "gemini-3.5-flash-lite", "gemini-flash-lite-latest", "gemini-flash-latest", "gemini-3.5-flash"]:
                    if pref in flash_models:
                        self.model_name = pref
                        return self.model_name
                    for cand in flash_models:
                        if pref in cand and "2.5" not in cand:
                            self.model_name = cand
                            return self.model_name
                if flash_models:
                    self.model_name = flash_models[0]
                    return self.model_name
        except Exception:
            pass
        return self.model_name

    def _call_gemini_api(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self.is_available():
            raise MissingAPIKeyError("GEMINI_API_KEY is not set or contains placeholder.")

        import requests
        import random

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"

        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.0}
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        max_attempts = 7
        for attempt in range(max_attempts):
            try:
                t_call = time.time()
                resp = requests.post(url, json=payload, timeout=35)
                call_lat = time.time() - t_call

                if resp.status_code == 200:
                    self.last_api_latency = call_lat
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                    raise MalformedResponseError(f"Unexpected response structure: {data}")
                elif resp.status_code in (429, 503, 500) or "RESOURCE_EXHAUSTED" in resp.text or "UNAVAILABLE" in resp.text:
                    if attempt < max_attempts - 1:
                        # Exponential backoff with jitter: 4s, 8s, 16s, 32s, 60s...
                        sleep_time = min(60.0, (2 ** (attempt + 2)) + random.uniform(1.0, 3.0))
                        time.sleep(sleep_time)
                        continue
                    raise RateLimitError(f"Rate limit exceeded (429/503) after {max_attempts} retries: {resp.text}")
                else:
                    raise LLMError(f"Gemini API returned status {resp.status_code}: {resp.text}")
            except requests.Timeout:
                if attempt < max_attempts - 1:
                    time.sleep(2)
                    continue
                raise LLMTimeoutError("Request timed out.")
            except requests.RequestException as re:
                if attempt < max_attempts - 1:
                    time.sleep(2)
                    continue
                raise LLMError(f"Network error calling Gemini: {re}")

        raise LLMError("Failed to generate response after retries.")

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        return self._call_gemini_api(prompt, system_prompt)


class LLMWrapper:
    """Unified wrapper handling caching, JSON extraction, and client dispatch."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model_name: Optional[str] = None,
        use_cache: bool = True,
        custom_client: Optional[BaseLLMClient] = None
    ):
        self.use_cache = use_cache
        target_model = model_name or os.getenv("LLM_MODEL", "gemini-2.5-flash")
        if custom_client:
            self.client = custom_client
        else:
            self.provider = (provider or os.getenv("LLM_PROVIDER", "gemini")).lower()
            if self.provider == "mock":
                self.client = MockLLMClient(target_model)
            else:
                self.client = GeminiLLMClient(target_model)

        if self.use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.last_cache_hit: bool = False
        self.total_llm_calls: int = 0
        self.last_call_count: int = 0

    def reset_stats(self):
        self.last_cache_hit = False
        self.last_call_count = 0

    def is_available(self) -> bool:
        return self.client.is_available()

    def discover_model(self) -> str:
        """Discover model from API if supported by client."""
        if hasattr(self.client, "discover_model"):
            return self.client.discover_model()
        return self.model_name

    @property
    def model_name(self) -> str:
        """Expose the underlying client's model name."""
        return getattr(self.client, "model_name", "unknown")

    @property
    def last_api_latency(self) -> float:
        """Expose actual network round-trip latency of the last API call."""
        return getattr(self.client, "last_api_latency", 0.0)

    @model_name.setter
    def model_name(self, value: str):
        if hasattr(self, "client") and self.client:
            self.client.model_name = value

    def _get_cache_key(self, prompt: str, system_prompt: Optional[str]) -> str:
        content = f"{self.client.model_name}::{system_prompt or ''}::{prompt}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _read_cache(self, key: str) -> Optional[str]:
        if not self.use_cache:
            return None
        cache_file = CACHE_DIR / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("response")
            except Exception:
                pass
        return None

    def _write_cache(self, key: str, response: str) -> None:
        if not self.use_cache:
            return
        cache_file = CACHE_DIR / f"{key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"response": response}, f)
        except Exception:
            pass

    def generate_text(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate text with disk cache and error protection."""
        cache_key = self._get_cache_key(prompt, system_prompt)
        cached = self._read_cache(cache_key)
        if cached is not None:
            self.last_cache_hit = True
            return cached

        self.last_cache_hit = False
        self.total_llm_calls += 1
        self.last_call_count += 1
        resp = self.client.generate(prompt, system_prompt)
        self._write_cache(cache_key, resp)
        return resp

    def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate structured JSON. Strips markdown fences and parses dictionary.
        Retries once if malformed.
        """
        raw_text = self.generate_text(prompt, system_prompt)

        # Clean markdown code block if present
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()

        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
            raise MalformedResponseError(f"Expected JSON object, got {type(parsed).__name__}")
        except json.JSONDecodeError as exc:
            # Retry once with explicit error correction prompt
            repair_prompt = (
                f"{prompt}\n\n"
                f"Your previous response was not valid JSON:\n{raw_text}\n\n"
                f"Fix the error and output ONLY a valid raw JSON object. Do not include markdown ticks."
            )
            retry_raw = self.client.generate(repair_prompt, system_prompt)
            cleaned_retry = retry_raw.strip()
            if cleaned_retry.startswith("```"):
                lines = cleaned_retry.splitlines()[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned_retry = "\n".join(lines).strip()
            try:
                parsed_retry = json.loads(cleaned_retry)
                if isinstance(parsed_retry, dict):
                    return parsed_retry
            except Exception:
                pass
            raise MalformedResponseError(f"Could not parse valid JSON from LLM: {exc}")
