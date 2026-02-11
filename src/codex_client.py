from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .codex_auth import load_codex_token
from .config import Config

CODEX_URL = "https://chatgpt.com/backend-api/codex/responses"
JWT_CLAIM_PATH = "https://api.openai.com/auth"


def _extract_account_id(jwt_token: str) -> str:
    # JWT: header.payload.signature (base64url)
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid jwt")
        payload_b64 = parts[1]
        # base64url padding
        pad = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
        account_id = payload.get(JWT_CLAIM_PATH, {}).get("chatgpt_account_id")
        if not account_id:
            raise ValueError("missing chatgpt_account_id")
        return account_id
    except Exception as e:
        raise RuntimeError("Failed to extract accountId from token") from e


def _to_responses_input(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert our internal history into the minimal OpenAI Responses input format.

    Supported internal message shapes:
    - {role:'user', content:str}
    - {role:'assistant', content:str}
    - {role:'assistant_toolcall', call_id, id, name, arguments_json}
    - {role:'tool', call_id, content:str}   # function_call_output
    """
    out: List[Dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "system":
            continue
        if role == "user":
            content = m.get("content") or ""
            out.append({"role": "user", "content": [{"type": "input_text", "text": content}]})
        elif role == "assistant":
            content = m.get("content") or ""
            if not content:
                continue
            out.append(
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content, "annotations": []}],
                    "status": "completed",
                    "id": m.get("id") or f"msg_{len(out)}",
                }
            )
        elif role == "assistant_toolcall":
            out.append(
                {
                    "type": "function_call",
                    "id": m.get("id"),
                    "call_id": m.get("call_id"),
                    "name": m.get("name"),
                    "arguments": m.get("arguments_json") or "{}",
                }
            )
        elif role == "tool":
            out.append(
                {
                    "type": "function_call_output",
                    "call_id": m.get("call_id"),
                    "output": m.get("content") or "",
                }
            )
    return out


@dataclass
class CodexResponse:
    text: str
    tool_calls: List[Dict[str, Any]]


def _parse_sse(stream: httpx.Response):
    # Yields parsed JSON events from text/event-stream
    for line in stream.iter_lines():
        if not line:
            continue
        if line.startswith(":"):
            continue
        if not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if data == "[DONE]":
            return
        try:
            yield json.loads(data)
        except Exception:
            # ignore malformed chunks
            continue


def codex_stream_once(cfg: Config, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> CodexResponse:
    token = load_codex_token()
    account_id = _extract_account_id(token.api_key)

    system_prompt = ""
    for m in messages:
        if m["role"] == "system":
            system_prompt = m.get("content") or ""
            break

    body: Dict[str, Any] = {
        "model": cfg.model,
        "store": False,
        "stream": True,
        "instructions": system_prompt,
        "input": _to_responses_input(messages),
        "text": {"verbosity": "medium"},
        "include": ["reasoning.encrypted_content"],
        "tool_choice": "auto",
        "parallel_tool_calls": True,
    }
    if tools:
        body["tools"] = tools

    headers = {
        "Authorization": f"Bearer {token.api_key}",
        "chatgpt-account-id": account_id,
        "OpenAI-Beta": "responses=experimental",
        "originator": "pi",
        "accept": "text/event-stream",
        "content-type": "application/json",
        "User-Agent": "shirmp (python)",
    }

    text_buf: List[str] = []
    tool_calls: List[Dict[str, Any]] = []

    with httpx.Client(timeout=60.0) as client:
        with client.stream("POST", CODEX_URL, headers=headers, json=body) as resp:
            if resp.status_code >= 400:
                # Read a small error body for diagnostics (don't include tokens)
                try:
                    err_text = resp.text
                except Exception:
                    err_text = ""
                raise httpx.HTTPStatusError(
                    f"Codex HTTP {resp.status_code}: {err_text[:2000]}",
                    request=resp.request,
                    response=resp,
                )
            current_tool: Optional[Dict[str, Any]] = None
            for evt in _parse_sse(resp):
                t = evt.get("type")
                if t == "response.output_text.delta":
                    delta = evt.get("delta") or ""
                    text_buf.append(delta)
                elif t == "response.output_item.added":
                    item = evt.get("item") or {}
                    if item.get("type") == "function_call":
                        current_tool = {
                            "call_id": item.get("call_id"),
                            "id": item.get("id"),
                            "name": item.get("name"),
                            "arguments_json": item.get("arguments") or "{}",
                        }
                elif t == "response.function_call_arguments.delta" and current_tool is not None:
                    current_tool["arguments_json"] = (current_tool.get("arguments_json") or "") + (evt.get("delta") or "")
                elif t == "response.output_item.done":
                    item = evt.get("item") or {}
                    if item.get("type") == "function_call":
                        # finalize
                        if current_tool is None:
                            current_tool = {
                                "call_id": item.get("call_id"),
                                "id": item.get("id"),
                                "name": item.get("name"),
                                "arguments_json": item.get("arguments") or "{}",
                            }
                        tool_calls.append(current_tool)
                        current_tool = None
                elif t == "response.completed":
                    break

    return CodexResponse(text="".join(text_buf), tool_calls=tool_calls)
