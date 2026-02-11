from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from .config import Config

OPENAI_RESPONSES_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/responses"


def _parse_sse(stream: httpx.Response):
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
            continue


def _to_responses_input(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Same transform as codex_client: keep it minimal and compatible with Responses API
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
class OpenAIResponse:
    text: str
    tool_calls: List[Dict[str, Any]]


def openai_stream_once(cfg: Config, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> OpenAIResponse:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

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
        "tool_choice": "auto",
        "parallel_tool_calls": True,
    }
    if tools:
        body["tools"] = tools

    headers = {
        "Authorization": f"Bearer {api_key}",
        "accept": "text/event-stream",
        "content-type": "application/json",
        "User-Agent": "shirmp (python)",
    }

    text_buf: List[str] = []
    tool_calls: List[Dict[str, Any]] = []

    with httpx.Client(timeout=60.0) as client:
        with client.stream("POST", OPENAI_RESPONSES_URL, headers=headers, json=body) as resp:
            resp.raise_for_status()
            current_tool: Optional[Dict[str, Any]] = None
            for evt in _parse_sse(resp):
                t = evt.get("type")
                if t == "response.output_text.delta":
                    text_buf.append(evt.get("delta") or "")
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

    return OpenAIResponse(text="".join(text_buf), tool_calls=tool_calls)
