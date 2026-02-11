from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from .config import Config


class ToolError(RuntimeError):
    pass


# ---- Tool argument schemas (Pydantic for validation) ----

class ReadFileArgs(BaseModel):
    path: str = Field(..., description="Path relative to workspace root or absolute")
    max_chars: int | None = Field(None, description="Truncate output to this many chars")


class WriteFileArgs(BaseModel):
    path: str = Field(..., description="Path relative to workspace root or absolute")
    content: str = Field(..., description="File content to write")
    overwrite: bool = Field(True, description="Overwrite if exists")


class ListDirArgs(BaseModel):
    path: str = Field(".", description="Directory path relative to workspace root or absolute")


class RunShellArgs(BaseModel):
    command: List[str] = Field(..., description="Command argv list, e.g. ['ls','-la']")
    cwd: str | None = Field(None, description="Working directory relative to workspace root")
    timeout_sec: int = Field(10, description="Timeout seconds")


@dataclass
class Tool:
    name: str
    description: str
    args_schema: type[BaseModel]
    handler: Callable[[BaseModel, Config], str]

    def json_schema(self) -> Dict[str, Any]:
        # Chat Completions tool schema format (function)
        schema = self.args_schema.model_json_schema()
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": schema.get("properties", {}),
                    "required": schema.get("required", []),
                },
            },
        }

    def responses_tool_schema(self) -> Dict[str, Any]:
        # OpenAI Responses-style tool schema
        schema = self.args_schema.model_json_schema()
        return {
            "type": "function",
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": schema.get("properties", {}),
                "required": schema.get("required", []),
            },
            "strict": False,
        }


def _resolve_path(p: str, cfg: Config) -> Path:
    path = Path(p).expanduser()
    if not path.is_absolute():
        path = (cfg.workspace_root / path).resolve()
    else:
        path = path.resolve()

    # Constrain to workspace_root for safety
    wr = cfg.workspace_root.resolve()
    if wr not in path.parents and path != wr:
        raise ToolError(f"Path escapes workspace_root: {path}")
    return path


def read_file(args: ReadFileArgs, cfg: Config) -> str:
    path = _resolve_path(args.path, cfg)
    data = path.read_text(encoding="utf-8", errors="replace")
    max_chars = args.max_chars or cfg.max_output_chars
    if len(data) > max_chars:
        data = data[:max_chars] + "\n…(truncated)…\n"
    return data


def write_file(args: WriteFileArgs, cfg: Config) -> str:
    path = _resolve_path(args.path, cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not args.overwrite:
        raise ToolError(f"File exists and overwrite=false: {path}")
    path.write_text(args.content, encoding="utf-8")
    return f"Wrote {len(args.content)} chars to {path}"


def list_dir(args: ListDirArgs, cfg: Config) -> str:
    path = _resolve_path(args.path, cfg)
    if not path.exists():
        raise ToolError(f"No such path: {path}")
    if not path.is_dir():
        raise ToolError(f"Not a directory: {path}")
    entries = []
    for p in sorted(path.iterdir()):
        entries.append({
            "name": p.name,
            "type": "dir" if p.is_dir() else "file",
            "size": p.stat().st_size,
        })
    return json.dumps(entries, ensure_ascii=False, indent=2)


def run_shell(args: RunShellArgs, cfg: Config) -> str:
    if not cfg.enable_run_shell:
        raise ToolError("run_shell is disabled by config")
    if not args.command:
        raise ToolError("Empty command")

    if cfg.shell_allowlist and args.command[0] not in cfg.shell_allowlist:
        raise ToolError(f"Command not in allowlist: {args.command[0]}")

    cwd = cfg.workspace_root
    if args.cwd:
        cwd = _resolve_path(args.cwd, cfg)

    # Execute with constrained cwd; capture output
    proc = subprocess.run(
        args.command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=args.timeout_sec,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    out = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
    out = out.strip("\n")

    if not out:
        out = "(no output)"

    if len(out) > cfg.max_output_chars:
        out = out[: cfg.max_output_chars] + "\n…(truncated)…"

    return f"exit_code={proc.returncode}\n" + out


def default_tools() -> List[Tool]:
    return [
        Tool(
            name="read_file",
            description="Read a UTF-8 text file within the workspace_root.",
            args_schema=ReadFileArgs,
            handler=read_file,
        ),
        Tool(
            name="write_file",
            description="Write a UTF-8 text file within the workspace_root.",
            args_schema=WriteFileArgs,
            handler=write_file,
        ),
        Tool(
            name="list_dir",
            description="List entries in a directory within the workspace_root.",
            args_schema=ListDirArgs,
            handler=list_dir,
        ),
        Tool(
            name="run_shell",
            description="Run a shell command (argv list) constrained to workspace_root. May be allowlisted.",
            args_schema=RunShellArgs,
            handler=run_shell,
        ),
    ]
