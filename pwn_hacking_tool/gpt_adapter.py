from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class GPTAdapterResult:
    ok: bool
    message: str
    output: str | None = None


def run_gpt_adapter(explain_payload: str, api_key: str | None = None) -> GPTAdapterResult:
    if not api_key:
        return GPTAdapterResult(ok=False, message="API key missing. Skipping GPT adapter.")
    return GPTAdapterResult(ok=False, message="GPT adapter not implemented for offline mode.")
