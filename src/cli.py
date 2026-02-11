from __future__ import annotations

import sys

from .config import Config
from .llm import Agent
from .tools import default_tools


def main() -> int:
    cfg = Config()

    print("shirmp (OpenClaw-like MVP) — console agent")
    print("Commands: /exit, /reset, /tools, /login")
    print("Auth: Codex OAuth (PKCE). Stores creds in ~/.clawdbot/auth-profiles.json; or env OPENAI_CODEX_API_KEY")

    try:
        agent = Agent(cfg, default_tools())
    except Exception as e:
        print(f"Fatal auth error: {e}")
        return 2

    while True:
        try:
            user = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            return 0

        if not user:
            continue
        if user == "/exit":
            print("bye")
            return 0
        if user == "/reset":
            agent.reset()
            print("(reset)")
            continue
        if user == "/tools":
            for t in default_tools():
                print(f"- {t.name}: {t.description}")
            continue

        if user == "/login":
            from .codex_oauth import login_openai_codex

            try:
                creds = login_openai_codex(debug=True)
                print("(login ok; creds saved)")
                # Re-init agent to pick up fresh token on next request
                agent = Agent(cfg, default_tools())
            except Exception as e:
                print(f"(login failed: {e})")
            continue

        out = agent.step(user)
        print(f"\nAda> {out}")


if __name__ == "__main__":
    raise SystemExit(main())
