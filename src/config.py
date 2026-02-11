from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    # Model name. For Codex OAuth backend, this should look like: "gpt-5.2" (or whatever your codex account supports)
    # For OpenAI API key mode, you can use e.g. "gpt-4o-mini".
    # Model name.
    # - Codex OAuth backend (chatgpt.com/backend-api/codex/responses): use a Codex-enabled model.
    # - OpenAI API key mode (api.openai.com/v1/responses): use a public platform model.
    # You can override at runtime with env: SHIRMP_MODEL
    model: str = "gpt-5.2"

    # Workspace root for file tools & shell restrictions
    workspace_root: Path = Path(__file__).resolve().parents[1]

    # Tool safety toggles
    enable_run_shell: bool = True

    # If set, only these commands are allowed (exact match on argv[0]).
    # Keep empty to allow any command (still constrained to workspace cwd).
    shell_allowlist: tuple[str, ...] = ("ls", "pwd", "cat", "echo", "python")

    # Maximum bytes to return for file reads / command output
    max_output_chars: int = 20_000
