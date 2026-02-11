from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx

# These values mirror OpenClaw's implementation (OpenClaw uses @mariozechner/pi-ai).
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
SCOPE = "openid profile email offline_access"
ORIGINATOR = "pi"

# IMPORTANT: OpenClaw uses localhost in the redirect_uri (not 127.0.0.1)
# Even though the callback server binds 127.0.0.1:1455.
REDIRECT_HOST = "127.0.0.1"
REDIRECT_PORT = 1455
REDIRECT_PATH = "/auth/callback"
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}{REDIRECT_PATH}"

# OpenClaw stores Codex OAuth profiles under ~/.openclaw/agents/main/agent/auth-profiles.json
# and ~/.clawdbot is often a symlink to ~/.openclaw.
# Prefer the OpenClaw path when present, otherwise fall back to ~/.clawdbot/auth-profiles.json.
OPENCLAW_AUTH_PATH = Path.home() / ".openclaw" / "agents" / "main" / "agent" / "auth-profiles.json"
DEFAULT_AUTH_PATH = OPENCLAW_AUTH_PATH if OPENCLAW_AUTH_PATH.exists() else (Path.home() / ".clawdbot" / "auth-profiles.json")



def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_pkce() -> tuple[str, str]:
    # code_verifier: high-entropy string (43-128 chars)
    verifier = _b64url_no_pad(secrets.token_bytes(32))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def create_state() -> str:
    return secrets.token_hex(16)


def parse_authorization_input(value: str) -> tuple[Optional[str], Optional[str]]:
    """Parse manual paste input.

    Mirrors OpenClaw/pi-ai behavior:
    - full redirect URL: http://localhost:1455/auth/callback?code=...&state=...
    - "code#state"
    - raw code
    """
    s = (value or "").strip()
    if not s:
        return None, None

    # Full URL
    try:
        u = urllib.parse.urlparse(s)
        if u.scheme and u.netloc:
            qs = urllib.parse.parse_qs(u.query)
            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [None])[0]
            return code, state
    except Exception:
        pass

    # code#state
    if "#" in s:
        code, st = s.split("#", 1)
        return code or None, st or None

    # querystring-ish
    if "code=" in s:
        qs = urllib.parse.parse_qs(s)
        code = (qs.get("code") or [None])[0]
        state = (qs.get("state") or [None])[0]
        return code, state

    return s, None


@dataclass
class OAuthCredentials:
    type: str  # "oauth"
    provider: str  # "openai-codex"
    access: str
    refresh: str
    expires: int  # ms epoch
    accountId: Optional[str] = None
    email: Optional[str] = None


class _CallbackResult:
    def __init__(self) -> None:
        self.code: Optional[str] = None
        self.state: Optional[str] = None
        self.error: Optional[str] = None
        self._event = threading.Event()

    def set(self, code: str | None, state: str | None, error: str | None = None) -> None:
        self.code = code
        self.state = state
        self.error = error
        self._event.set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def _make_handler(expected_state: str, result: _CallbackResult):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            try:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != REDIRECT_PATH:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                    return

                qs = urllib.parse.parse_qs(parsed.query)
                state = (qs.get("state") or [None])[0]
                code = (qs.get("code") or [None])[0]

                if state != expected_state:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"State mismatch")
                    result.set(None, state, "state_mismatch")
                    return

                if not code:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing code")
                    result.set(None, state, "missing_code")
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<!doctype html><html><body><p>Authentication successful. Return to your terminal.</p></body></html>"
                )
                result.set(code, state, None)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal error")
                result.set(None, None, f"server_error:{e}")

        def log_message(self, fmt, *args):
            # Silence default logging
            return

    return Handler


def _start_local_server(expected_state: str, timeout_sec: int) -> tuple[_CallbackResult, Optional[HTTPServer], Optional[threading.Thread]]:
    result = _CallbackResult()
    handler = _make_handler(expected_state, result)
    try:
        httpd = HTTPServer((REDIRECT_HOST, REDIRECT_PORT), handler)
    except OSError as e:
        # Mirror OpenClaw fallback: if we can't bind, we'll ask for manual paste.
        result.set(None, None, f"bind_failed:{e}")
        return result, None, None

    def run():
        # Handle requests until result set or timeout
        end = time.time() + timeout_sec
        httpd.timeout = 0.5
        while time.time() < end and not result._event.is_set():
            httpd.handle_request()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return result, httpd, t


def build_authorize_url(code_challenge: str, state: str) -> str:
    # Match OpenClaw/pi-ai: always include the Codex flags.
    q: Dict[str, str] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": ORIGINATOR,
    }
    return AUTHORIZE_URL + "?" + urllib.parse.urlencode(q)


def _redact_token(s: str) -> str:
    if not s:
        return s
    # Keep a short prefix/suffix for debugging without leaking secrets
    if len(s) <= 16:
        return "***"
    return s[:6] + "…" + s[-6:]


def _redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if k in {"access_token", "refresh_token", "id_token"} and isinstance(v, str):
            out[k] = _redact_token(v)
        else:
            out[k] = v
    return out


def exchange_code_for_token(code: str, verifier: str, *, debug: bool = False) -> OAuthCredentials:
    form = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }
    if debug:
        print("[codex-oauth] POST /oauth/token (exchange)")
        print("  url:", TOKEN_URL)
        print("  form:", {**form, "code": _redact_token(form["code"]), "code_verifier": _redact_token(form["code_verifier"])})

    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form,
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"code->token failed: {resp.status_code} {resp.text}")
    data = resp.json()
    if debug:
        print("[codex-oauth] token response:", _redact_dict(data))
    access = data.get("access_token")
    refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")
    if not access or not refresh or not isinstance(expires_in, (int, float)):
        raise RuntimeError(f"token response missing fields: {data}")

    return OAuthCredentials(
        type="oauth",
        provider="openai-codex",
        access=access,
        refresh=refresh,
        expires=int(time.time() * 1000 + float(expires_in) * 1000),
    )


def refresh_access_token(creds: OAuthCredentials, *, debug: bool = False) -> OAuthCredentials:
    form = {
        "grant_type": "refresh_token",
        "refresh_token": creds.refresh,
        "client_id": CLIENT_ID,
    }
    if debug:
        print("[codex-oauth] POST /oauth/token (refresh)")
        print("  url:", TOKEN_URL)
        print("  form:", {**form, "refresh_token": _redact_token(form["refresh_token"])})

    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form,
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"refresh failed: {resp.status_code} {resp.text}")
    data = resp.json()
    if debug:
        print("[codex-oauth] refresh response:", _redact_dict(data))
    access = data.get("access_token")
    refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")
    if not access or not refresh or not isinstance(expires_in, (int, float)):
        raise RuntimeError(f"refresh response missing fields: {data}")

    return OAuthCredentials(
        type="oauth",
        provider="openai-codex",
        access=access,
        refresh=refresh,
        expires=int(time.time() * 1000 + float(expires_in) * 1000),
        accountId=creds.accountId,
        email=creds.email,
    )


def _load_store(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"profiles": {}}
    raw = path.read_text("utf-8")
    return json.loads(raw) if raw.strip() else {"profiles": {}}


def _save_store(path: Path, store: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def save_profile(creds: OAuthCredentials, profile_id: str = "openai-codex:default", auth_path: Path = DEFAULT_AUTH_PATH) -> None:
    store = _load_store(auth_path)
    store.setdefault("profiles", {})
    store["profiles"][profile_id] = {
        "type": "oauth",
        "provider": "openai-codex",
        "access": creds.access,
        "refresh": creds.refresh,
        "expires": creds.expires,
        **({"accountId": creds.accountId} if creds.accountId else {}),
        **({"email": creds.email} if creds.email else {}),
    }
    _save_store(auth_path, store)


def login_openai_codex(
    auth_path: Path = DEFAULT_AUTH_PATH,
    profile_id: str = "openai-codex:default",
    timeout_sec: int = 300,
    open_browser: bool = True,
    *,
    debug: bool = False,
) -> OAuthCredentials:
    verifier, challenge = generate_pkce()
    state = create_state()
    url = build_authorize_url(challenge, state)

    result, httpd, thread = _start_local_server(state, timeout_sec=timeout_sec)

    try:
        if debug:
            print("[codex-oauth] authorize url:")
            print(url)
            print("[codex-oauth] redirect_uri:", REDIRECT_URI)
            print("[codex-oauth] state:", state)
        if open_browser:
            webbrowser.open(url)
        else:
            print(url)

        # If we couldn't bind the callback server, fall back to manual paste.
        if httpd is None:
            pasted = input("Paste the full redirect URL (or code#state): ").strip()
            code, st = parse_authorization_input(pasted)
            if st and st != state:
                raise RuntimeError("State mismatch")
            if not code:
                raise RuntimeError("No authorization code received")
            creds = exchange_code_for_token(code, verifier, debug=debug)
            save_profile(creds, profile_id=profile_id, auth_path=auth_path)
            return creds

        ok = result.wait(timeout=timeout_sec)
        if not ok:
            raise RuntimeError("OAuth login timed out")
        if result.error:
            # If callback reported something like bind_failed, allow manual paste.
            if str(result.error).startswith("bind_failed:"):
                pasted = input("Paste the full redirect URL (or code#state): ").strip()
                code, st = parse_authorization_input(pasted)
                if st and st != state:
                    raise RuntimeError("State mismatch")
                if not code:
                    raise RuntimeError("No authorization code received")
                creds = exchange_code_for_token(code, verifier, debug=debug)
                save_profile(creds, profile_id=profile_id, auth_path=auth_path)
                return creds
            raise RuntimeError(f"OAuth callback error: {result.error}")
        if not result.code:
            raise RuntimeError("No authorization code received")

        creds = exchange_code_for_token(result.code, verifier, debug=debug)
        save_profile(creds, profile_id=profile_id, auth_path=auth_path)
        return creds
    finally:
        try:
            if httpd is not None:
                httpd.server_close()
        except Exception:
            pass


def load_profile(auth_path: Path = DEFAULT_AUTH_PATH) -> tuple[str, OAuthCredentials]:
    store = _load_store(auth_path)
    profiles = store.get("profiles") or {}
    for profile_id, cred in profiles.items():
        if not isinstance(profile_id, str) or not profile_id.startswith("openai-codex:"):
            continue
        if not isinstance(cred, dict):
            continue
        if cred.get("type") != "oauth" or cred.get("provider") != "openai-codex":
            continue
        return profile_id, OAuthCredentials(
            type="oauth",
            provider="openai-codex",
            access=str(cred.get("access") or ""),
            refresh=str(cred.get("refresh") or ""),
            expires=int(cred.get("expires") or 0),
            accountId=cred.get("accountId"),
            email=cred.get("email"),
        )
    raise RuntimeError(f"No openai-codex oauth profile found in {auth_path}")


def ensure_fresh_token(auth_path: Path = DEFAULT_AUTH_PATH, *, debug: bool = False) -> tuple[str, OAuthCredentials]:
    profile_id, creds = load_profile(auth_path)
    if int(time.time() * 1000) >= int(creds.expires):
        new_creds = refresh_access_token(creds, debug=debug)
        save_profile(new_creds, profile_id=profile_id, auth_path=auth_path)
        return profile_id, new_creds
    return profile_id, creds
