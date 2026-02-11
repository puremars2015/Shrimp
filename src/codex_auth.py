from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .codex_oauth import DEFAULT_AUTH_PATH, ensure_fresh_token


@dataclass
class CodexToken:
    api_key: str  # JWT access token
    source: str  # env|oauth_store
    auth_path: Optional[str] = None
    profile_id: Optional[str] = None


def load_codex_token() -> CodexToken:
    # Allow override for testing / CI
    env = os.environ.get("OPENAI_CODEX_API_KEY")
    if env:
        return CodexToken(api_key=env, source="env")

    auth_path = Path(os.environ.get("CLAWDBOT_AUTH_PATH", str(DEFAULT_AUTH_PATH)))
    debug = os.environ.get("SHIRMP_CODEX_DEBUG") == "1"
    profile_id, creds = ensure_fresh_token(auth_path, debug=debug)
    return CodexToken(api_key=creds.access, source="oauth_store", auth_path=str(auth_path), profile_id=profile_id)
