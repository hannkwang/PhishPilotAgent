# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then set ANTHROPIC_API_KEY
```

`urllib3` is pinned to `<2` in `requirements.txt` — macOS Python 3.9 ships with LibreSSL, which urllib3 v2 rejects.

## Running

```bash
# Pass a .eml file
.venv/bin/python main.py sample1.eml

# Pipe raw email or URL text
echo "Click here: http://evil-login.com" | .venv/bin/python main.py

# Interactive paste (Ctrl+D to submit)
.venv/bin/python main.py
```

There are no tests or linters configured.

## Architecture

**Entry point:** `main.py` reads input (file arg, stdin pipe, or interactive paste) via `get_input()`, then calls `run_agent()` in the same file. All agent logic lives in `main.py`.

**Agentic loop:** `run_agent()` drives a bounded `for iteration in range(MAX_ITERATIONS)` loop calling `client.messages.create()` on each turn. The Python code is purely mechanical — it runs whatever tools Claude requests, feeds results back, and loops. All investigation strategy and verdict reasoning happen inside Claude, not in the loop. `MAX_ITERATIONS = 10` is a hard ceiling; the loop normally exits early via `return` when `submit_verdict` is called or `stop_reason == "end_turn"`.

**Pre-extraction step:** Before the first API call, `ioc_extractor.run()` parses the raw input for URLs, IPs, domains, and email addresses. The extracted IOCs are injected into the first user message alongside the raw input so Claude starts with a structured head start rather than re-parsing text itself.

**Tool dispatch flow:**
1. Claude calls `check_url_reputation` → `tools/urlscan.py` queries Spamhaus DBL + SURBL via DNS and scans the URL for suspicious keywords; returns DNSBL hit flags and keyword matches
2. Claude calls `check_ip_reputation` → `tools/abuseipdb.py` hits ip-api.com (proxy/VPN/hosting detection) and Shodan InternetDB (open ports, vuln tags); both are keyless
3. Claude calls `check_domain_reputation` → `tools/virustotal.py` queries Spamhaus DBL + SURBL via DNS and RDAP for domain registration age and registrar; keyless
4. Claude calls `check_email_headers` → `tools/header_parser.py` parses SPF/DKIM/DMARC from `Authentication-Results` headers and extracts routing hops from `Received` headers; no network calls
5. Claude calls `submit_verdict` → caught directly in the loop, not dispatched to a tool file; triggers `print_verdict()` and exits

**Critical agentic loop invariants** (in `run_agent()`):
- The full `response.content` list (not just text) must be appended as the assistant message — `tool_use` blocks must be preserved so the API can match them to `tool_result` responses
- All tool results for a single turn go back in **one** user message as a list of `{"type": "tool_result", "tool_use_id": block.id, "content": result}` dicts — `block.id` must match exactly
- Claude may request multiple tools in a single response; all are executed before sending results back
- `submit_verdict` is intercepted before reaching `execute_tool()` — it is a sentinel, not a real dispatch; returning immediately after calling `print_verdict()` is what exits the loop cleanly
- `stop_reason == "max_tokens"` is non-fatal: the loop logs a warning and continues to the next iteration rather than treating it as terminal

**Tool definitions** (inline in `main.py` as the `TOOLS` list) are raw JSON schema dicts passed directly to `client.messages.create(tools=...)`. The descriptions are what guide Claude's tool-calling strategy. `submit_verdict` is included in `TOOLS` with an enum-constrained `verdict` field to force machine-parseable output — Claude is explicitly told in the system prompt to call it exactly once.

**IOC extraction** (`tools/ioc_extractor.py`):
- Refangs common obfuscation before scanning: `hxxp://` → `http://`, `[.]` → `.`, `[@]` → `@`
- Deduplicates URLs, IPs, emails using set comprehensions; results are sorted lists
- Filters private/loopback IPv4 ranges (`10.x`, `172.16–31.x`, `192.168.x`, `127.x`, `0.x`) — only public IPs are returned
- Domains are derived from URLs and email sender domains via `tldextract` to get the registrable root (e.g. `login.evil.com` → `evil.com`)

**Shared HTTP session** (`tools/http.py`): a single `requests.Session` with a `Retry` adapter (3 retries, 2s/4s/8s backoff, on 429/500/502/503/504) is instantiated once at module load and reused across all tool calls. `abuseipdb.py` and `virustotal.py` import `SESSION` from this module.

**DNS blocklist checks** (`tools/urlscan.py`, `tools/virustotal.py`): URIBL was deliberately dropped from both — it returns `127.0.0.1` for all queries when accessed via public DNS resolvers, producing false positives. Only Spamhaus DBL and SURBL are queried. A DNS resolution success (not NXDOMAIN) means the domain is listed.

**RDAP lookups** (`tools/virustotal.py`): `rdap.org` is avoided (Cloudflare-blocked). Instead, TLD-specific RDAP servers are queried directly (`rdap.verisign.com` for `.com`/`.net`, `rdap.publicinterestregistry.org` for `.org`). Domain age is computed from the `registration` event date. Only `.com`, `.net`, `.org` TLDs have RDAP entries configured; others return `domain_age_days: null`.

**Output safety** (`tools/defang.py`): `defang()` rewrites `http://` → `hxxp://`, `https://` → `hxxps://`, `.` → `[.]` before printing IOCs to the terminal. Applied in `print_verdict()` to evidence strings and the recommended action.

**Logging** (`main.py`, `config.py`): each `run_agent()` call creates two timestamped log files under `logs/`:
- `logs/agent_<YYYYMMDD_HHMMSS>.log` — agentic loop events: `[START]` with IOCs and model, `[ITER N]` with stop reason / input+output token counts / wall-clock latency, `[END]` or `[VERDICT]` at exit, `[WARN]` for max_tokens and MAX_ITERATIONS
- `logs/tools_<YYYYMMDD_HHMMSS>.log` — function-level events: `[TOOL]` with full input JSON before each dispatch, `[RESULT]` with char count and 150-char preview after, `[ERROR]` with traceback on exception

Both loggers use `propagate = False` and file-only handlers (no root logger involvement). Console output stays as `print()`. The `logs/` directory is gitignored.

## External API Dependencies

| API | URL | Auth | Used for |
|-----|-----|------|----------|
| ip-api.com | `http://ip-api.com/json/<ip>` | None | Geolocation, proxy/VPN/hosting flags |
| Shodan InternetDB | `https://internetdb.shodan.io/<ip>` | None | Open ports, vuln tags, hostnames |
| Spamhaus DBL | DNS: `<domain>.dbl.spamhaus.org` | None | URL/domain blocklist |
| SURBL | DNS: `<domain>.multi.surbl.org` | None | URL/domain blocklist |
| RDAP (Verisign/PIR) | TLD-specific endpoints | None | Domain registration age, registrar |

All APIs are unauthenticated. ip-api.com free tier is HTTP-only and rate-limited to 45 req/min; the shared retry adapter handles transient failures.

## Adding a New Tool

Three locations must change in lockstep:

1. **`tools/<name>.py`** — implement the function; return a JSON string (`json.dumps(...)`)
2. **`main.py` `TOOLS` list** — add a JSON schema dict with `name`, `description`, and `input_schema`; the description is what Claude reads to decide when to call it
3. **`main.py` `execute_tool()`** — add an `elif name == "<name>"` branch dispatching to the new function

If the tool should only be available conditionally (e.g. gated on a flag), omit it from `TOOLS` at construction time rather than guarding inside `execute_tool()`.

## Where the Autonomy Lives

The Python loop has no intelligence — it runs tools on demand and loops. Claude is the autonomous actor. On every iteration, Claude decides:

- **Which tools to call** — the system prompt instructs Claude to investigate every IOC, but the code enforces nothing; Claude chooses order and grouping
- **Whether to call `check_email_headers`** — only if raw headers are present in the input; Claude makes this judgment from context
- **How many tool calls to make per iteration** — the code handles any number; Claude decides when it has enough evidence
- **When to stop** — no code tells Claude "you're done"; Claude decides when to call `submit_verdict`
- **The verdict reasoning itself** — signal combination (DNSBL hits, domain age, IP flags, auth headers) happens in Claude's reasoning, not in Python

## Verdict Logic

Defined entirely in `prompts/system_prompt.txt`:

| Verdict | Condition |
|---------|-----------|
| `MALICIOUS` | DNSBL hit on URL or domain, **or** SPF/DMARC fail + domain age < 30 days + hosting/VPN IP |
| `SUSPICIOUS` | Mixed signals: hosting IP + new domain, SPF fail alone, or many suspicious keywords |
| `CLEAN` | No DNSBL hits, domain age > 180 days, no proxy/hosting/VPN flags, auth headers pass |

Confidence (`High` / `Medium` / `Low`) and `recommended_action` are free-form fields Claude populates based on the weight of evidence. The `submit_verdict` tool schema enforces the enum on `verdict` only.
