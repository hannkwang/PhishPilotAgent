# PhishPilot-Agent - Build Plan (v2, Opus 4.8 reviewed)

## Project Overview

Agentic phishing analyser that accepts a raw email or URL, autonomously investigates all
IOCs using external APIs, and returns a structured triage verdict. Built on the Anthropic
Claude API using the tool_use agentic loop pattern.

Model: claude-sonnet-4-6 (chosen for low cost on high-volume phishing triage). Sonnet 4.6
balances quality and cost well, which suits a tool that may process many emails per day.
Adaptive thinking only - do NOT pass temperature, top_p, or budget_tokens (removed in 4.6+).
Native structured_outputs supported. Max tokens capped at 4096 per call.

---

## What Changed from v1 (review summary)

| # | Fix | Why |
|---|---|---|
| 1 | Added MAX_ITERATIONS cap on loop | Prevents runaway token spend |
| 2 | try/except in every tool wrapper | One API failure no longer crashes the run |
| 3 | extract_iocs moved to pre-loop local call | Pure regex, no I/O - no reason to spend an LLM round-trip on it |
| 4 | URLScan async poll handled explicitly | Returns UUID then polls result endpoint |
| 5 | Defanging applied to all output | Safe to paste verdicts into logs/tickets |
| 6 | Built-in retry + rate-limit backoff | VT free tier = 4/min; handled, not foot-noted |
| 7 | .gitignore + key-presence guard | Secrets never committed; fails fast if key missing |
| 8 | Structured JSON verdict via tool schema | Pipeable into SIEM/ticketing |
| 9 | Verified model string + params | claude-sonnet-4-6 for low cost, adaptive thinking only |

---

## Repository Structure

```
PhishPilot-Agent/
├── main.py                  # entry point + agentic loop
├── config.py                # env loading + key guards
├── tools/
│   ├── __init__.py
│   ├── ioc_extractor.py     # regex IOC parser (called pre-loop, not via LLM)
│   ├── urlscan.py           # URLScan.io: submit + poll
│   ├── abuseipdb.py         # AbuseIPDB API wrapper
│   ├── virustotal.py        # VirusTotal API wrapper
│   ├── header_parser.py     # SPF/DKIM/DMARC parser
│   ├── defang.py            # IOC defanging helper
│   └── http.py              # shared session w/ retry + backoff
├── prompts/
│   └── system_prompt.txt
├── .env                     # API keys (gitignored)
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Architecture Decision: extract_iocs is NOT an LLM tool

In v1, extract_iocs was a tool Claude had to call. It's pure local regex with zero external
I/O. Routing it through the model wastes one full request/response cycle. Instead:

1. Run extract_iocs locally BEFORE the loop starts.
2. Inject the extracted IOCs directly into the first user message.
3. Claude starts already knowing the IOCs and only spends tool calls on the reputation
   lookups that actually need external data.

This is the "hardcode what you can draw the flowchart for" principle - IOC extraction is
deterministic, so it stays out of the agentic loop.

---

## Tools (the 4 that need the loop)

| Tool | API / Method | Returns |
|---|---|---|
| check_url_reputation | URLScan.io - submit then poll | Verdict, categories, screenshot link |
| check_ip_reputation | AbuseIPDB | Abuse confidence score, country |
| check_domain_reputation | VirusTotal | Vendor verdicts, domain age |
| check_email_headers | Local parse (kept as tool: Claude decides if headers present) | SPF/DKIM/DMARC, hops |

---

## Tool JSON Schemas

### check_url_reputation
```json
{
  "name": "check_url_reputation",
  "description": "Check URL reputation via URLScan.io. Submits scan, polls for result. Returns verdict, categories, threat indicators.",
  "input_schema": {
    "type": "object",
    "properties": {
      "url": { "type": "string", "description": "Full URL to scan (defanged or live)" }
    },
    "required": ["url"]
  }
}
```

### check_ip_reputation
```json
{
  "name": "check_ip_reputation",
  "description": "Check IP reputation via AbuseIPDB. Returns abuse confidence score (0-100) and country.",
  "input_schema": {
    "type": "object",
    "properties": {
      "ip": { "type": "string", "description": "IPv4 or IPv6 address" }
    },
    "required": ["ip"]
  }
}
```

### check_domain_reputation
```json
{
  "name": "check_domain_reputation",
  "description": "Check domain reputation via VirusTotal. Returns vendor verdicts and domain registration age in days.",
  "input_schema": {
    "type": "object",
    "properties": {
      "domain": { "type": "string", "description": "Domain name (e.g. evil.com)" }
    },
    "required": ["domain"]
  }
}
```

### check_email_headers
```json
{
  "name": "check_email_headers",
  "description": "Parse email headers for SPF, DKIM, DMARC results and routing hop analysis. Call only if raw email headers are present.",
  "input_schema": {
    "type": "object",
    "properties": {
      "raw_headers": { "type": "string", "description": "Raw email header block" }
    },
    "required": ["raw_headers"]
  }
}
```

### submit_verdict (structured output, forces clean final result)
```json
{
  "name": "submit_verdict",
  "description": "Submit the final phishing triage verdict. Call this exactly once when investigation is complete.",
  "input_schema": {
    "type": "object",
    "properties": {
      "verdict": { "type": "string", "enum": ["MALICIOUS", "SUSPICIOUS", "CLEAN"] },
      "confidence": { "type": "string", "enum": ["High", "Medium", "Low"] },
      "evidence": { "type": "array", "items": { "type": "string" } },
      "recommended_action": { "type": "string" }
    },
    "required": ["verdict", "confidence", "evidence", "recommended_action"]
  }
}
```

Using a submit_verdict tool (rather than free text) gives a guaranteed machine-parseable
result that drops straight into a ticket or SIEM field. The loop terminates when this tool
is called.

---

## Shared HTTP with Retry - tools/http.py

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,            # 2s, 4s, 8s between retries
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()
```

Every tool wrapper uses SESSION and wraps its call in try/except, returning a JSON error
string rather than raising - so a single failing lookup degrades gracefully instead of
killing the run.

---

## Config + Key Guard - config.py

```python
import os
from dotenv import load_dotenv

load_dotenv()

REQUIRED_KEYS = [
    "ANTHROPIC_API_KEY",
    "URLSCAN_API_KEY",
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
]

def check_keys():
    missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
    if missing:
        raise SystemExit(f"Missing required env keys: {', '.join(missing)}")

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
MAX_ITERATIONS = 10        # hard cap on agentic loop turns
```

---

## Defanging - tools/defang.py

```python
def defang(text: str) -> str:
    """Render IOCs safe to paste into logs/terminals."""
    return (text.replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace(".", "[.]"))
```

Apply to all IOCs in the final verdict before printing or logging.

---

## Agentic Loop - main.py

```python
import json
import anthropic
from config import MODEL, MAX_TOKENS, MAX_ITERATIONS, check_keys
from tools import ioc_extractor, urlscan, abuseipdb, virustotal, header_parser, defang

check_keys()
client = anthropic.Anthropic()

TOOLS = [
    # paste check_url_reputation, check_ip_reputation, check_domain_reputation,
    # check_email_headers, submit_verdict schemas here
]

SYSTEM_PROMPT = open("prompts/system_prompt.txt").read()

def execute_tool(name: str, tool_input: dict) -> str:
    try:
        if name == "check_url_reputation":
            return urlscan.run(tool_input["url"])
        elif name == "check_ip_reputation":
            return abuseipdb.run(tool_input["ip"])
        elif name == "check_domain_reputation":
            return virustotal.run(tool_input["domain"])
        elif name == "check_email_headers":
            return header_parser.run(tool_input["raw_headers"])
        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": str(e), "tool": name})

def print_verdict(v: dict):
    print(f"VERDICT: {v['verdict']}")
    print(f"CONFIDENCE: {v['confidence']}")
    print("EVIDENCE:")
    for e in v["evidence"]:
        print(f"  - {defang.defang(e)}")
    print(f"RECOMMENDED ACTION: {defang.defang(v['recommended_action'])}")

def run_agent(user_input: str):
    # Step 1: extract IOCs locally (deterministic, no LLM round-trip)
    iocs = ioc_extractor.run(user_input)

    first_msg = (
        f"Raw input:\n{user_input}\n\n"
        f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
        f"Investigate every IOC, then call submit_verdict."
    )
    messages = [{"role": "user", "content": first_msg}]

    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Claude finished without calling submit_verdict - print any text
            for block in response.content:
                if getattr(block, "type", None) == "text":
                    print(block.text)
            return

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if block.name == "submit_verdict":
                        print_verdict(block.input)   # final structured result
                        return
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})

    print("WARNING: hit MAX_ITERATIONS without a verdict. Review messages manually.")

if __name__ == "__main__":
    sample = input("Paste email or URL: ")
    run_agent(sample)
```

---

## URLScan Async Handling - tools/urlscan.py

```python
import os, time, json
from .http import SESSION

def run(url: str) -> str:
    headers = {"API-Key": os.getenv("URLSCAN_API_KEY"), "Content-Type": "application/json"}
    submit = SESSION.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        json={"url": url, "visibility": "private"},
        timeout=30,
    )
    submit.raise_for_status()
    result_url = submit.json()["api"]   # poll this

    # URLScan needs ~10-30s to finish the scan
    for _ in range(6):
        time.sleep(5)
        r = SESSION.get(result_url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            verdict = data.get("verdicts", {}).get("overall", {})
            return json.dumps({
                "malicious": verdict.get("malicious"),
                "score": verdict.get("score"),
                "categories": verdict.get("categories", []),
            })
    return json.dumps({"error": "URLScan result not ready after polling"})
```

Note `"visibility": "private"` - never submit government-context URLs as public scans.

---

## System Prompt - prompts/system_prompt.txt

```
You are PhishPilot, a phishing analysis agent for a government security team.

Input: a raw email or URL, plus pre-extracted IOCs.

Process:
- Investigate every IOC using the reputation tools - skip none.
- If raw email headers are present, call check_email_headers.
- Call tools in parallel when investigating multiple independent IOCs.
- Never guess. Base your verdict only on tool results.
- If a tool returns an error, note it as a gap and continue with remaining evidence.

When investigation is complete, call submit_verdict exactly once. Do not write a
free-text verdict - use the submit_verdict tool so the result is machine-parseable.

Verdict guidance:
- MALICIOUS: confirmed bad reputation, SPF/DMARC fail + new domain, high abuse score.
- SUSPICIOUS: mixed signals, insufficient evidence either way.
- CLEAN: all checks pass, established domain, no abuse history.
```

---

## .gitignore

```
.env
__pycache__/
*.pyc
.venv/
```

---

## .env.example

```
ANTHROPIC_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

---

## Dependencies - requirements.txt

```
anthropic
requests
python-dotenv
urllib3
```

---

## API Reference

| Service | Free Tier | Endpoint |
|---|---|---|
| URLScan.io | 100 scans/day | https://urlscan.io/api/v1/scan/ |
| AbuseIPDB | 1000 checks/day | https://api.abuseipdb.com/api/v2/check |
| VirusTotal | 500/day, 4/min | https://www.virustotal.com/api/v3/domains/{domain} |

---

## Build Order

| Step | Task | Est. time |
|---|---|---|
| 1 | Scaffold repo, .gitignore, config.py with key guard | 20 min |
| 2 | tools/http.py shared session + retry | 15 min |
| 3 | ioc_extractor.py regex (URL/IP/domain/email) | 30 min |
| 4 | defang.py helper | 10 min |
| 5 | header_parser.py (SPF/DKIM/DMARC) | 45 min |
| 6 | abuseipdb.py wrapper | 20 min |
| 7 | virustotal.py wrapper | 20 min |
| 8 | urlscan.py submit + poll | 35 min |
| 9 | main.py agentic loop with submit_verdict + iteration cap | 50 min |
| 10 | Test with phishtank.org samples | 30 min |

Total: ~4.5 hours

---

## Test Samples

- https://phishtank.org - verified phishing URLs
- https://openphish.com - live phishing feed

Always set URLScan visibility to private for any work-context sample.

---

## Notes for Claude Code

- `pip install -r requirements.txt` before starting.
- Model is claude-sonnet-4-6 (low cost): adaptive thinking only, no temperature/top_p/budget_tokens.
- All tool wrappers return JSON strings; on failure return {"error": ...}, never raise.
- submit_verdict tool call is the loop's terminal condition - not stop_reason alone.
- MAX_ITERATIONS=10 is a safety cap; a normal run finishes in 2-4 turns.
- Defang every IOC before printing or logging.
- VirusTotal free tier is 4 req/min - the retry/backoff in http.py absorbs 429s.
