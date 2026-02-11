# shirmp — OpenClaw-like MVP (Python)

這是一個「類 OpenClaw」的極簡 MVP：
- **Console** 互動式聊天
- 透過 **OpenAI API** 呼叫 LLM
- 支援 **tool calling**（模型可要求執行工具；程式執行後把結果回傳給模型）
- 附幾個最基本工具：讀檔、寫檔、列目錄、跑 shell（可關閉/限制）

## 需求
- Python 3.10+
- 預設使用 **OpenAI Codex / ChatGPT OAuth**（PKCE + localhost callback）
  - 若你已經用 OpenClaw 登入過，shirmp 會優先讀取：`~/.openclaw/agents/main/agent/auth-profiles.json`
  - 否則才用：`~/.clawdbot/auth-profiles.json`
- 或自行設定環境變數：`OPENAI_CODEX_API_KEY`（JWT access token）
- 若要改用 **OpenAI API Key**（`https://api.openai.com/v1/responses`），請另外設定：
  - `OPENAI_API_KEY=...`
  - `SHIRMP_USE_OPENAI_API=1`

## 安裝
```bash
cd /Users/maenqi/shirmp
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 執行
```bash
python -m src.cli
```

## 使用
- 直接輸入訊息 Enter。
- 指令：
  - `/login` 登入（會印出 debug log；token 會遮罩不洩漏）

### 常見問題（OAuth）
- 如果瀏覽器顯示「驗證時發生錯誤 (unknown_error)」，最常見原因是 `redirect_uri` 使用了 `127.0.0.1`。
  - OpenClaw / pi-ai 使用 `http://localhost:1455/auth/callback`，shirmp 也已跟隨這個做法。
  - `/exit` 離開
  - `/reset` 清空對話
  - `/tools` 列出可用工具

### Debug
- `/login` 會印出 authorize URL、redirect_uri、以及 code→token exchange 的 request/response（遮罩 token）
- 設 `SHIRMP_CODEX_DEBUG=1` 會在 refresh 時也印出 refresh 的 request/response（遮罩 token）

## 登入機制（純 Python，技術重點）
這個 MVP 走 **Codex OAuth（ChatGPT OAuth）**，流程是：
1. 產生 **PKCE**：`code_verifier` + `code_challenge(S256)`
2. 開瀏覽器導向 `https://auth.openai.com/oauth/authorize?...`（帶 `client_id`, `redirect_uri`, `scope`, `code_challenge`, `state`…）
3. 本機起一個 `http://127.0.0.1:1455/auth/callback` 接回 `code`
4. 用 `code + code_verifier` POST 到 `https://auth.openai.com/oauth/token` 換 token
5. 把 `{access, refresh, expires}` 存到 `~/.clawdbot/auth-profiles.json`（profileId 預設 `openai-codex:default`）
6. 每次呼叫前若過期，用 `refresh_token` 再打一次 `/oauth/token` refresh
7. 用 `access_token`（JWT）呼叫 `https://chatgpt.com/backend-api/codex/responses`

實作在：`src/codex_oauth.py`

## 安全提醒
`run_shell` 工具可能有風險；預設只允許在專案目錄下執行，且可在 `src/config.py` 內關閉或加嚴 allowlist。
