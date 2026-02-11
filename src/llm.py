from __future__ import annotations

import json
from typing import Any, Dict, List

from .config import Config
from .tools import Tool, ToolError
import os

from .codex_client import codex_stream_once
from .openai_client import openai_stream_once


SYSTEM_PROMPT = """You are an assistant running in a small agent runtime.
You may call tools to read/write files, list directories, or run safe shell commands.
Be concise. If you need to inspect files or run commands, use the available tools.
"""


class Agent:
    def __init__(self, cfg: Config, tools: List[Tool]):
        self.cfg = cfg
        self.tools = {t.name: t for t in tools}
        # Codex Responses tool schema
        self.responses_tools = [t.responses_tool_schema() for t in tools]
        self.messages: List[Dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    def reset(self) -> None:
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def _execute_tool(self, name: str, arguments_json: str) -> str:
        if name not in self.tools:
            raise ToolError(f"Unknown tool: {name}")
        tool = self.tools[name]
        args_dict = json.loads(arguments_json or "{}")
        args = tool.args_schema.model_validate(args_dict)
        return tool.handler(args, self.cfg)

    def step(self, user_text: str) -> str:
        self.messages.append({"role": "user", "content": user_text})

        # Loop: Codex Responses -> optional tool calls -> tool outputs -> Codex ...
        for _ in range(8):
            # Routing:
            # - Default: Codex OAuth backend (chatgpt.com/backend-api/codex/responses)
            # - Opt-in: OpenAI API key backend (api.openai.com/v1/responses) by setting SHIRMP_USE_OPENAI_API=1
            use_openai_api = os.environ.get("SHIRMP_USE_OPENAI_API") == "1"
            # Allow model override via env without editing code
            model_override = os.environ.get("SHIRMP_MODEL")
            if model_override:
                self.cfg = type(self.cfg)(
                    model=model_override,
                    workspace_root=self.cfg.workspace_root,
                    enable_run_shell=self.cfg.enable_run_shell,
                    shell_allowlist=self.cfg.shell_allowlist,
                    max_output_chars=self.cfg.max_output_chars,
                )

            if use_openai_api:
                r = openai_stream_once(self.cfg, self.messages, tools=self.responses_tools)
            else:
                r = codex_stream_once(self.cfg, self.messages, tools=self.responses_tools)

            # Save assistant text (if any)
            if r.text:
                self.messages.append({"role": "assistant", "content": r.text})

            if not r.tool_calls:
                return r.text or ""

            # Execute tool calls and append both the function_call item and its output
            for tc in r.tool_calls:
                name = tc.get("name")
                call_id = tc.get("call_id")
                tool_id = tc.get("id")
                args_json = tc.get("arguments_json") or "{}"

                # Record the model's function_call so the next request can be paired with output
                self.messages.append(
                    {
                        "role": "assistant_toolcall",
                        "call_id": call_id,
                        "id": tool_id,
                        "name": name,
                        "arguments_json": args_json,
                    }
                )

                try:
                    result = self._execute_tool(name, args_json)
                except Exception as e:
                    result = f"TOOL_ERROR: {type(e).__name__}: {e}"

                self.messages.append({"role": "tool", "call_id": call_id, "content": result})

        return "(stopped: too many tool-call iterations)"
