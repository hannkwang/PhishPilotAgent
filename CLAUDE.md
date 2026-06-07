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

**Entry point:** `main.py` reads input (file arg, stdin pipe, or interactive paste) via `get_input()`, then calls `run_chain()` in the same file. All agent logic lives in `main.py`.

**Agent pattern:** `run_chain()` implements a **prompt chain** (sequential workflow): three fixed steps executed in order, each a separate `client.messages.create()` call with a scoped task. Python controls the sequence and step transitions; Claude's role is scoped per step. This contrasts with `run_agent()` (also in `main.py`) which is the original dynamic agent where Claude drives all tool calls autonomously.

**Pre-extraction step:** Before Step 1, `ioc_extractor.run()` parses the raw input for URLs, IPs, domains, and email addresses. The extracted IOCs are passed into every step.

**Prompt chain — three steps:**

**Step 1 — Triage** (`prompts/triage_prompt.txt`): One API call. Claude receives the raw input and extracted IOCs. It must call `produce_triage_plan` exactly once (enforced by `tool_choice={"type": "any"}`), returning a structured list of tool calls to execute (e.g. `[{"tool": "check_url_reputation", "input": {"url": "..."}}]`). Claude decides whether email headers are present and whether to include `check_email_headers`. No tool execution happens here.

**Step 2 — Gather** (no API call): Python iterates `plan["tools_needed"]` from Step 1 and calls `execute_tool()` for each item in sequence. The order and set of calls are fully determined by the Step 1 plan — Claude has no role in this step. Results accumulate in an `evidence` dict keyed by `tool_name(input)`.

**Step 3 — Verdict** (`prompts/verdict_prompt.txt`): One API call. Claude receives the raw input, IOCs, and the full `evidence` block from Step 2. It must call `submit_verdict` exactly once (enforced by `tool_choice={"type": "any"}` with only `submit_verdict` offered). Python calls `print_verdict()` on the result and exits.

**Tool definitions** (inline in `main.py`):
- `TOOLS` — the four investigation tools + `submit_verdict`; used by `run_agent()` and by Step 3 (submit_verdict only)
- `TRIAGE_TOOL` — `produce_triage_plan` schema used only in Step 1; forces Claude to output a machine-parseable plan rather than free text

**Prompt files:**
- `prompts/system_prompt.txt` — used by `run_agent()` (original dynamic agent); instructs Claude on tool-use strategy, parallelism, and verdict logic
- `prompts/triage_prompt.txt` — used by Step 1; scoped to plan enumeration only, no reasoning
- `prompts/verdict_prompt.txt` — used by Step 3; scoped to verdict synthesis only, no tool-use strategy

**Tool dispatch** (`execute_tool()` in `main.py`): unchanged from the original. Maps tool name → function call in `tools/`. Used by both `run_agent()` and `run_chain()` Step 2.

**IOC extraction** (`tools/ioc_extractor.py`):
- Refangs common obfuscation before scanning: `hxxp://` → `http://`, `[.]` → `.`, `[@]` → `@`
- Deduplicates URLs, IPs, emails using set comprehensions; results are sorted lists
- Filters private/loopback IPv4 ranges (`10.x`, `172.16–31.x`, `192.168.x`, `127.x`, `0.x`) — only public IPs are returned
- Domains are derived from URLs and email sender domains via `tldextract` to get the registrable root (e.g. `login.evil.com` → `evil.com`)

**Shared HTTP session** (`tools/http.py`): a single `requests.Session` with a `Retry` adapter (3 retries, 2s/4s/8s backoff, on 429/500/502/503/504) is instantiated once at module load and reused across all tool calls. `abuseipdb.py` and `virustotal.py` import `SESSION` from this module.

**DNS blocklist checks** (`tools/urlscan.py`, `tools/virustotal.py`): URIBL was deliberately dropped from both — it returns `127.0.0.1` for all queries when accessed via public DNS resolvers, producing false positives. Only Spamhaus DBL and SURBL are queried. A DNS resolution success (not NXDOMAIN) means the domain is listed.

**RDAP lookups** (`tools/virustotal.py`): `rdap.org` is avoided (Cloudflare-blocked). Instead, TLD-specific RDAP servers are queried directly (`rdap.verisign.com` for `.com`/`.net`, `rdap.publicinterestregistry.org` for `.org`). Domain age is computed from the `registration` event date. Only `.com`, `.net`, `.org` TLDs have RDAP entries configured; others return `domain_age_days: null`.

**Output safety** (`tools/defang.py`): `defang()` rewrites `http://` → `hxxp://`, `https://` → `hxxps://`, `.` → `[.]` before printing IOCs to the terminal. Applied in `print_verdict()` to evidence strings and the recommended action.

**Logging** (`main.py`, `config.py`): each `run_chain()` call creates two timestamped log files under `logs/`:
- `logs/agent_<YYYYMMDD_HHMMSS>.log` — chain events: `[START]` with IOCs and model, `[STEP 1]` with triage plan + token counts + latency, `[STEP 2]` with evidence count, `[STEP 3]` with token counts + latency, `[VERDICT]` at exit, `[WARN]` on abort
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

In `run_chain()`, autonomy is split between Python and Claude by step:

**Python controls (enforced by code):**
- Step sequence — Triage → Gather → Verdict always runs in that order
- Which tools are offered per step — Claude cannot call investigation tools in Step 3 or `submit_verdict` in Step 1
- Tool execution in Step 2 — Python iterates the plan and calls `execute_tool()` directly; Claude has no role
- Step transitions — Python assembles the evidence block and constructs Step 3's input from Step 2's output

**Claude decides (within each step's scope):**
- Step 1: Which IOCs to include in the plan, whether email headers are present, what order to list tool calls
- Step 3: The verdict itself — signal combination (DNSBL hits, domain age, IP flags, auth results), confidence level, evidence bullets, recommended action

**Contrast with `run_agent()` (original dynamic agent):** the Python loop has no intelligence — it runs tools on demand and loops. Claude is the autonomous actor deciding which tools to call, whether to check email headers, how many calls to make per iteration, and when to stop. All intelligence lives inside Claude, not in the loop.

## Verdict Logic

Defined in `prompts/verdict_prompt.txt` (used by `run_chain()` Step 3) and `prompts/system_prompt.txt` (used by `run_agent()`):

| Verdict | Condition |
|---------|-----------|
| `MALICIOUS` | DNSBL hit on URL or domain, **or** SPF/DMARC fail + domain age < 30 days + hosting/VPN IP |
| `SUSPICIOUS` | Mixed signals: hosting IP + new domain, SPF fail alone, or many suspicious keywords |
| `CLEAN` | No DNSBL hits, domain age > 180 days, no proxy/hosting/VPN flags, auth headers pass |

Confidence (`High` / `Medium` / `Low`) and `recommended_action` are free-form fields Claude populates based on the weight of evidence. The `submit_verdict` tool schema enforces the enum on `verdict` only.
