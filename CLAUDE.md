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

There are no tests or linters configured. `sample1.eml` and `sample2.eml` are real phishing samples (Bradesco and Mashreq bank impersonation); both should verdict MALICIOUS — use them as regression checks after changing prompts or tools.

## The Agentic Loop

**Entry point:** `main.py` reads input via `get_input()` and calls `run_chain()`. All agent logic lives in `main.py`.

`run_chain()` is a **prompt chain with one bounded feedback edge**. The pipeline:

```
                 ┌─ Python ─┐   ┌─ Claude ─┐   ┌──── Python ────┐   ┌─ Claude ─┐
  raw input ──► extract IOCs ──► Step 1     ──► Step 2: Gather  ──► Step 3     ──► verdict
                (+ MIME decode,  Triage:        (parallel tool       Verdict:
                 unwrap          plan tool      execution)           weigh signals,
                 redirectors)    calls            │      ▲           submit_verdict
                                                  ▼      │
                                              Step 2b: Follow-up
                                              (re-extract IOCs from
                                               evidence; ≤5 calls,
                                               one round, no API)
```

Each LLM step is a separate `client.messages.create()` call with a scoped task and a forced tool call. Python owns the control flow; Claude's judgment is confined to two decision points.

**Pre-extraction (Python, no API call):** `ioc_extractor.run()` parses the raw input. For raw emails it MIME-decodes body parts (quoted-printable/base64 — payload URLs are usually invisible without this), extracts `href`/`src` from HTML, unwraps known redirectors (Bing `/ck/a`, Safe Links, Google redirect, urldefense v3) to expose the real target, and tags shared-infrastructure domains (`SHARED_INFRA`) whose clean reputation carries no signal. Extracted IOCs are passed into every step.

**Step 1 — Triage (Claude, 1 API call):** `prompts/triage_prompt.txt`. Claude receives the raw input + IOCs and must call `produce_triage_plan` exactly once (`tool_choice={"type": "any"}` with only `TRIAGE_TOOL` offered), returning a machine-parseable list of tool calls. Claude's judgment here: which IOCs are worth checking (skip shared infra and template noise, always include redirect targets), whether headers/body are present for `check_email_headers` / `analyze_brand_impersonation`. For those two tools the plan passes `{}` — the runtime injects the raw email in `execute_tool()`, so the model never has to echo the full email back (token cost, lossy).

**Step 2 — Gather (Python, no API call):** `_run_tool_calls()` validates each plan item (malformed/unknown/duplicate items are skipped with a warning, *before* execution), then executes via `execute_tool()` in a `ThreadPoolExecutor` (all tools are pure network I/O). Results accumulate in an `evidence` dict keyed by `tool_name(sorted-json-input)`; an `executed` set tracks keys across batches.

**Step 2b — Follow-up (Python, no API call):** the feedback edge. `_plan_followups()` re-runs the IOC extractor over the gathered evidence — redirect targets, rDNS hostnames from Shodan, hop IPs only surface in tool results — and deterministically maps each *new* IOC to its tool (url→`check_url_reputation`, etc.). Bounded by design: one round only, `MAX_FOLLOWUP_CALLS` cap, shared-infra skipped, the `executed` set prevents repeats. This recovers the main advantage of a dynamic agent (reacting to what evidence reveals) without giving up the chain's predictability or spending an API call.

**Step 3 — Verdict (Claude, 1 API call):** `prompts/verdict_prompt.txt`. Claude receives raw input, IOCs, and the full evidence block, and must call `submit_verdict` exactly once (`tool_choice="any"`, only `submit_verdict` offered). Claude's judgment here: weighing the signal rubric (see Verdict Logic), confidence, evidence bullets, recommended action. `print_verdict()` defangs and prints.

**Reliability:** Steps 1 and 3 go through `_forced_tool_call()`, which retries once with corrective feedback if the model fails to call the required tool, and aborts cleanly on `max_tokens`.

### Where the Autonomy Lives

**Python controls (enforced by code):** step sequence; which tools are offered per step (Claude cannot call investigation tools in Step 3 or `submit_verdict` in Step 1); all tool execution, validation, dedup, and parallelism; the follow-up round's existence and bounds; assembly of each step's input from the previous step's output.

**Claude decides (within each step's scope):** Step 1 — which IOCs make the plan and which are noise. Step 3 — the verdict: signal combination, confidence, evidence, action.

**Contrast — `run_agent()` (original dynamic agent, kept in `main.py`):** a bare tool-use loop where Claude is the autonomous actor: it decides which tools to call, in what order, how many per iteration, and when to stop (by calling `submit_verdict`). The Python loop has no intelligence — it executes whatever Claude asks (up to `MAX_ITERATIONS`) and feeds results back. Uses `prompts/system_prompt.txt`. On `max_tokens` truncation it strips incomplete `tool_use` blocks before continuing (the API rejects `tool_use` without a matching `tool_result`).

## Tools

**Tool definitions** (inline in `main.py`): `TOOLS` holds the five investigation tools + `submit_verdict` (used by `run_agent()`; Step 3 offers only `submit_verdict`). `TRIAGE_TOOL` is the `produce_triage_plan` schema used only in Step 1. `INVESTIGATION_TOOL_NAMES` is the allowlist `_run_tool_calls()` validates against.

**Tool dispatch** (`execute_tool()` in `main.py`): maps tool name → function in `tools/`. Takes a `raw_input` fallback: `check_email_headers` and `analyze_brand_impersonation` receive the full raw input when their plan input is `{}`.

| Tool | Module | Checks |
|------|--------|--------|
| `check_url_reputation` | `tools/urlscan.py` | DNSBLs on the URL's root domain, suspicious keywords, subdomain depth |
| `check_ip_reputation` | `tools/abuseipdb.py` | ip-api.com (geo, proxy/VPN/hosting flags) + Shodan InternetDB (ports, vulns) |
| `check_domain_reputation` | `tools/virustotal.py` | DNSBLs + RDAP domain age/registrar |
| `check_email_headers` | `tools/header_parser.py` | SPF/DKIM/DMARC, From/Reply-To/Return-Path alignment, vendor spam scores (SCL/BCL), hops |
| `analyze_brand_impersonation` | `tools/brand_check.py` | From display name vs sender registrable domain; body link/image domains; brand assets hotlinked from a domain that isn't the sender's |

**DNSBL checks** (`tools/dnsbl.py`, shared by `urlscan.py` and `virustotal.py`): queries Spamhaus DBL and SURBL and **validates the returned A record** — Spamhaus `127.0.1.x` = listed but `127.255.255.x` = query error (public-resolver refusal), SURBL `127.0.0.x` = listed except `127.0.0.1` = error. Treating any resolution as a hit causes systematic false positives on networks using public DNS. URIBL deliberately dropped (returns `127.0.0.1` for everything via public resolvers).

**RDAP lookups** (`tools/virustotal.py`): the IANA bootstrap registry (`data.iana.org/rdap/dns.json`, fetched once per process, thread-safe) maps ~1,200 TLDs to their RDAP servers; a hardcoded `.com/.net/.org` map is the fallback. `rdap.org` is avoided (Cloudflare-blocked). Some TLDs (e.g. `.me`, `.tc`) have no RDAP service at all — `domain_age_days: null` is expected there, and the verdict rubric treats unknown age on an unusual TLD as mildly suspicious, never exculpatory.

**IOC extraction** (`tools/ioc_extractor.py`): refangs (`hxxp://`, `[.]`, `[@]`), MIME-decodes email bodies, parses HTML links, unwraps redirectors (`unwrap_redirect()`, bounded to 3 nested layers), dedupes/lowercases, filters private IPv4 ranges, derives registrable root domains via `tldextract`. Returns `urls`, `ips`, `domains`, `emails`, `redirects` (wrapper→target pairs), and `shared_infra_domains`. `decode_email_body()` and `extract_html_links()` are exported for reuse (`brand_check.py` imports them).

**Shared HTTP session** (`tools/http.py`): one `requests.Session` with a Retry adapter (3 retries, 2s/4s/8s backoff on 429/5xx), reused across all tool calls.

**Output safety** (`tools/defang.py`): `defang()` rewrites `http://` → `hxxp://`, `.` → `[.]` before printing IOCs; applied in `print_verdict()`.

## Logging

Each run creates two timestamped files under `logs/` (gitignored):
- `logs/agent_<ts>.log` — chain events: `[START]`, `[STEP 1]`/`[STEP 3]` with attempt number, token counts, latency, `[STEP 2]`/`[STEP 2b]` evidence counts, `[VERDICT]`, `[WARN]` on skips/aborts
- `logs/tools_<ts>.log` — `[TOOL]` input JSON, `[RESULT]` char count + 150-char preview, `[ERROR]` with traceback

Both loggers use `propagate = False` and file-only handlers. Console output stays as `print()`.

## External API Dependencies

| API | URL | Auth | Used for |
|-----|-----|------|----------|
| ip-api.com | `http://ip-api.com/json/<ip>` | None | Geolocation, proxy/VPN/hosting flags |
| Shodan InternetDB | `https://internetdb.shodan.io/<ip>` | None | Open ports, vuln tags, hostnames |
| Spamhaus DBL | DNS: `<domain>.dbl.spamhaus.org` | None | Domain blocklist |
| SURBL | DNS: `<domain>.multi.surbl.org` | None | Domain blocklist |
| IANA RDAP bootstrap | `https://data.iana.org/rdap/dns.json` | None | TLD → RDAP server map |
| RDAP (per-TLD) | from bootstrap | None | Domain registration age, registrar |

All APIs are unauthenticated. ip-api.com free tier is HTTP-only and rate-limited to 45 req/min; the shared retry adapter handles transient failures. Step 2 runs up to `MAX_PARALLEL_TOOLS` (4) calls concurrently.

## Adding a New Tool

Four locations must change in lockstep:

1. **`tools/<name>.py`** — implement the function; return a JSON string (`json.dumps(...)`)
2. **`main.py` `TOOLS` list** — add the JSON schema dict; the description is what Claude reads to decide when to call it
3. **`main.py` `TRIAGE_TOOL` enum + `INVESTIGATION_TOOL_NAMES`** — so Step 1 can plan it and Step 2 will accept it
4. **`main.py` `execute_tool()`** — add the dispatch branch

If the tool needs the full raw input (like the header/brand tools), dispatch with `tool_input.get(...) or raw_input` and document "pass {}" in the schema description, so plans stay small.

## Verdict Logic

Defined in `prompts/verdict_prompt.txt` (Step 3) and mirrored in `prompts/system_prompt.txt` (`run_agent()`). A **weighted rubric**, not fixed conjunctions — true positives rarely light up every signal at once (e.g. domain age is often unavailable on exotic TLDs):

- **Strong signals** — any one is sufficient for MALICIOUS: a DNSBL hit; brand impersonation combined with any auth failure; a payload URL hidden behind a redirector pointing at an unrelated domain.
- **Moderate signals** — 3+ → MALICIOUS, 1–2 → SUSPICIOUS: SPF/DKIM/DMARC fail or none; hosting/proxy/VPN sender IP; domain age < 30 days; vendor spam score (SCL ≥ 5 / BCL ≥ 4); Reply-To/Return-Path misalignment; urgency or filter-evasion keywords; unknown domain age on an unusual TLD.
- **CLEAN** requires all of: no strong signals, no DNSBL hits, domain age > 180 days, auth passes, no brand mismatch, no IP flags.
- **Discount rules:** clean reputation on shared infrastructure carries no weight (judge the redirect target, not the wrapper); a DNSBL miss is not exculpatory; hotlinked brand images from the real brand domain are evidence of impersonation, not legitimacy.

The `submit_verdict` schema enforces the enum on `verdict` only; `confidence` and `recommended_action` are free-form fields Claude populates from the weight of evidence.
