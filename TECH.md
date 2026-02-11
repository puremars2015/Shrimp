技術面：Codex OAuth（ChatGPT OAuth）怎麼運作（你要的重點）
這套是標準 OAuth 2.0 + PKCE：

### ⚠️ 重要坑：redirect_uri 的 host 要用 `localhost`（跟 OpenClaw 一樣）
我們一開始用 `http://127.0.0.1:1455/auth/callback` 雖然理論上等價，但實測在 OpenAI 的 auth UI 會遇到：
- 「驗證時發生錯誤 (unknown_error)」

OpenClaw / pi-ai 的 hardcode 是：
- `REDIRECT_URI = http://localhost:1455/auth/callback`

所以 shirmp 也必須跟著用 `localhost` 才能穩定完成授權。
（本機 callback server 仍可綁 `127.0.0.1:1455` 監聽，不衝突。）

產生 PKCE
code_verifier：高熵隨機字串
code_challenge = BASE64URL(SHA256(code_verifier))
打開授權頁（Authorize）
導向（開瀏覽器）：
https://auth.openai.com/oauth/authorize?...
帶參數：

client_id（Codex/ChatGPT 的 client id）
redirect_uri = http://127.0.0.1:1455/auth/callback
scope = openid profile email offline_access（offline_access 才有 refresh token）
code_challenge, code_challenge_method=S256
state（防 CSRF）
以及一些 codex flow 的 flags（我照 reference 里的）
本機接 callback
你的程式在本機起 HTTP server 監聽：
http://127.0.0.1:1455/auth/callback
瀏覽器登入完後會 redirect 回來帶：

?code=...&state=...
用 code 換 token（Token endpoint）
POST 到：
https://auth.openai.com/oauth/token
Content-Type: application/x-www-form-urlencoded
body：

grant_type=authorization_code
client_id=...
code=...
code_verifier=...
redirect_uri=...
會拿到：

access_token（JWT）
refresh_token
expires_in
refresh（到期自動換新）
到期後用 refresh token 再 POST 一次同個 endpoint：
grant_type=refresh_token
refresh_token=...
client_id=...
呼叫 Codex backend
拿 access_token（JWT）去打：
https://chatgpt.com/backend-api/codex/responses
並且要從 JWT payload 解析出：
https://api.openai.com/auth.chatgpt_account_id
放到 header：chatgpt-account-id

你專案裡對應的實作檔
src/codex_oauth.py：完整 OAuth login + refresh + 寫入 ~/.clawdbot/auth-profiles.json
src/codex_auth.py：載入 profile，必要時 refresh，吐出可用 JWT
src/codex_client.py：用 JWT 呼叫 .../codex/responses（SSE 串流）
src/cli.py：多了 /login 指令（會開瀏覽器做 OAuth）
src/llm.py：agent loop（tool calling）仍在
我也已經把先前的 scripts/get_codex_token.mjs 和 package.json 砍掉了。

怎麼用
cd /Users/maenqi/shirmp
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m src.cli
第一次進去後輸入：

/login：會開瀏覽器登入，成功後 creds 會存到 ~/.clawdbot/auth-profiles.json
接著就能直接聊天呼叫 codex。