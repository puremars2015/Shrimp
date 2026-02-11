from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover
    keyring = None


SERVICE_NAME = "shirmp-openai"
ACCOUNT_NAME = "default"


@dataclass
class AuthState:
    api_key: Optional[str]
    source: str  # env|keyring|none


def load_api_key() -> AuthState:
    # 1) Env always wins
    env = os.environ.get("OPENAI_API_KEY")
    if env:
        return AuthState(api_key=env, source="env")

    # 2) Keychain via keyring
    if keyring is not None:
        try:
            v = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
            if v:
                return AuthState(api_key=v, source="keyring")
        except Exception:
            pass

    return AuthState(api_key=None, source="none")


def save_api_key(api_key: str) -> None:
    if keyring is None:
        raise RuntimeError("keyring not installed; pip install keyring")
    keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, api_key)


def clear_api_key() -> None:
    if keyring is None:
        return
    try:
        keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME)
    except Exception:
        pass
