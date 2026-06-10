import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import anthropic
from config import MODEL, MAX_TOKENS, MAX_ITERATIONS, check_keys, setup_loggers
from tools import ioc_extractor, urlscan, abuseipdb, virustotal, header_parser, brand_check, defang

check_keys()
client = anthropic.Anthropic()

# Follow-up round (Step 2b) limits: one round only, capped call count, so the
# feedback edge cannot loop or fan out unboundedly.
MAX_FOLLOWUP_CALLS = 5
MAX_PARALLEL_TOOLS = 4

TOOLS = [
    {
        "name": "check_url_reputation",
        "description": "Check URL reputation via DNS blocklists (Spamhaus DBL, SURBL). Returns DNSBL hits and suspicious keyword signals.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to check (defanged or live)"}
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_ip_reputation",
        "description": "Check IP reputation via ip-api.com (proxy/VPN/hosting detection) and Shodan InternetDB (open ports, vulns, tags).",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address"}
            },
            "required": ["ip"],
        },
    },
    {
        "name": "check_domain_reputation",
        "description": "Check domain reputation via DNS blocklists (Spamhaus DBL, SURBL) and RDAP (domain age and registrar).",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name (e.g. evil.com)"}
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_email_headers",
        "description": "Parse email headers for SPF/DKIM/DMARC results, From/Reply-To/Return-Path alignment, vendor spam scores (SCL/BCL), and routing hops. Call only if raw email headers are present. Pass {} — the runtime supplies the raw email automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_headers": {"type": "string", "description": "Raw email header block (optional; supplied automatically when omitted)"}
            },
        },
    },
    {
        "name": "analyze_brand_impersonation",
        "description": "Compare the brand the email claims to be from (From display name, subject, hotlinked logo/image domains) against the actual sender domain and body link domains. Call when the input is a raw email with body content. Pass {} — the runtime supplies the raw email automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_email": {"type": "string", "description": "Raw email (optional; supplied automatically when omitted)"}
            },
        },
    },
    {
        "name": "submit_verdict",
        "description": "Submit the final phishing triage verdict. Call this exactly once when investigation is complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["MALICIOUS", "SUSPICIOUS", "CLEAN"]},
                "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "recommended_action": {"type": "string"},
            },
            "required": ["verdict", "confidence", "evidence", "recommended_action"],
        },
    },
]

INVESTIGATION_TOOL_NAMES = {
    "check_url_reputation",
    "check_ip_reputation",
    "check_domain_reputation",
    "check_email_headers",
    "analyze_brand_impersonation",
}

_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "system_prompt.txt")
with open(_PROMPT_PATH) as _f:
    SYSTEM_PROMPT = _f.read()

_TRIAGE_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "triage_prompt.txt")
with open(_TRIAGE_PROMPT_PATH) as _f:
    TRIAGE_PROMPT = _f.read()

_VERDICT_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "verdict_prompt.txt")
with open(_VERDICT_PROMPT_PATH) as _f:
    VERDICT_PROMPT = _f.read()

# Tool used only in run_chain() Step 1 to force structured plan output from Claude.
TRIAGE_TOOL = {
    "name": "produce_triage_plan",
    "description": "Output the investigation plan: which tools to call for which IOCs. Call exactly once.",
    "input_schema": {
        "type": "object",
        "properties": {
            "tools_needed": {
                "type": "array",
                "description": "Ordered list of tool calls to execute",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "enum": [
                                "check_url_reputation",
                                "check_ip_reputation",
                                "check_domain_reputation",
                                "check_email_headers",
                                "analyze_brand_impersonation",
                            ],
                        },
                        "input": {
                            "type": "object",
                            "description": "Input parameters for the tool (e.g. {\"url\": \"https://example.com\"}). Pass {} for check_email_headers and analyze_brand_impersonation.",
                        },
                    },
                    "required": ["tool", "input"],
                },
            },
        },
        "required": ["tools_needed"],
    },
}


def execute_tool(name: str, tool_input: dict, tool_log, raw_input: str = "") -> str:
    try:
        if name == "check_url_reputation":
            return urlscan.run(tool_input["url"])
        elif name == "check_ip_reputation":
            return abuseipdb.run(tool_input["ip"])
        elif name == "check_domain_reputation":
            return virustotal.run(tool_input["domain"])
        elif name == "check_email_headers":
            # The plan passes {} so it doesn't have to echo the full email
            # back through the model; the runtime injects the raw input here.
            return header_parser.run(tool_input.get("raw_headers") or raw_input)
        elif name == "analyze_brand_impersonation":
            return brand_check.run(tool_input.get("raw_email") or raw_input)
        else:
            tool_log.error("[ERROR] Unknown tool: %s", name)
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        tool_log.error("[ERROR] %s raised: %s", name, e, exc_info=True)
        print(f"    [!] {name} error: {e}")
        return json.dumps({"error": str(e), "tool": name})


def print_verdict(v: dict, agent_log):
    verdict = v.get("verdict", "UNKNOWN")
    confidence = v.get("confidence", "Unknown")
    evidence = v.get("evidence") or []
    action = v.get("recommended_action", "(no action provided)")
    agent_log.info(
        "[VERDICT] verdict=%s  confidence=%s  action=%s",
        verdict, confidence, defang.defang(action),
    )
    for e in evidence:
        agent_log.info("[VERDICT]   evidence: %s", defang.defang(e))
    print("\n" + "=" * 50)
    print(f"VERDICT:    {verdict}")
    print(f"CONFIDENCE: {confidence}")
    print("EVIDENCE:")
    for e in evidence:
        print(f"  - {defang.defang(e)}")
    print(f"ACTION:     {defang.defang(action)}")
    print("=" * 50)


def run_agent(user_input: str):
    agent_log, tool_log = setup_loggers()

    iocs = ioc_extractor.run(user_input)
    agent_log.info("[START] IOCs=%s  model=%s", json.dumps(iocs), MODEL)
    print(f"[*] Extracted IOCs: {json.dumps(iocs)}")

    first_msg = (
        f"Raw input:\n{user_input}\n\n"
        f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
        "Investigate every IOC, then call submit_verdict."
    )
    messages = [{"role": "user", "content": first_msg}]

    for iteration in range(MAX_ITERATIONS):
        t0 = time.monotonic()
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        elapsed = time.monotonic() - t0
        usage = response.usage
        agent_log.info(
            "[ITER %d] stop_reason=%s  tokens=in:%d out:%d  latency=%.2fs",
            iteration + 1, response.stop_reason,
            usage.input_tokens, usage.output_tokens, elapsed,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            agent_log.info("[END] Agent reached end_turn after %d iteration(s)", iteration + 1)
            for block in response.content:
                if getattr(block, "type", None) == "text":
                    print(block.text)
            return

        elif response.stop_reason == "max_tokens":
            agent_log.warning("[WARN] Response hit max_tokens on iteration %d; continuing", iteration + 1)
            print("WARNING: response hit max_tokens; continuing loop.")
            # A truncated turn may end mid-tool_use; the API rejects tool_use
            # blocks without matching tool_results, so keep only text blocks.
            text_blocks = [b for b in response.content if getattr(b, "type", None) == "text"]
            messages[-1] = {
                "role": "assistant",
                "content": text_blocks or [{"type": "text", "text": "(response truncated)"}],
            }
            # Must add a user turn to maintain alternating-role invariant before next API call.
            messages.append({"role": "user", "content": "Continue."})
            continue

        elif response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if block.name == "submit_verdict":
                        agent_log.info("[END] submit_verdict called after %d iteration(s)", iteration + 1)
                        print_verdict(block.input, agent_log)
                        return
                    tool_log.info("[TOOL]   %s  input=%s", block.name, json.dumps(block.input))
                    print(f"[*] Calling {block.name}({json.dumps(block.input)})")
                    result = execute_tool(block.name, block.input, tool_log, user_input)
                    preview = result[:150] + ("..." if len(result) > 150 else "")
                    tool_log.info("[RESULT] %s  (%d chars) %s", block.name, len(result), preview)
                    print(f"    -> {preview}")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})

        else:
            agent_log.warning("[WARN] Unexpected stop_reason=%r on iteration %d; aborting", response.stop_reason, iteration + 1)
            print(f"WARNING: unexpected stop_reason={response.stop_reason!r}. Aborting.")
            return

    agent_log.warning("[WARN] Hit MAX_ITERATIONS (%d) without a verdict", MAX_ITERATIONS)
    print("WARNING: hit MAX_ITERATIONS without a verdict. Review logs/ for full trace.")


def _forced_tool_call(step_label: str, system: str, tools: list, user_content: str,
                      want_tool: str, agent_log):
    """Make an API call that must invoke `want_tool` (tool_choice=any).
    Retries once with corrective feedback if the model fails to call it.
    Returns (tool_input_or_None, last_response)."""
    messages = [{"role": "user", "content": user_content}]
    response = None
    for attempt in (1, 2):
        t0 = time.monotonic()
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            tools=tools,
            tool_choice={"type": "any"},
            messages=messages,
        )
        elapsed = time.monotonic() - t0
        usage = response.usage
        agent_log.info(
            "[%s] attempt=%d  stop_reason=%s  tokens=in:%d out:%d  latency=%.2fs",
            step_label, attempt, response.stop_reason,
            usage.input_tokens, usage.output_tokens, elapsed,
        )
        if response.stop_reason == "max_tokens":
            agent_log.warning("[WARN] %s hit max_tokens; %s was not called", step_label, want_tool)
            print(f"WARNING: {step_label} hit max_tokens before calling {want_tool} — re-run or increase MAX_TOKENS.")
            return None, response
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == want_tool:
                return block.input, response
        if attempt == 1:
            agent_log.warning("[WARN] %s did not call %s; retrying once", step_label, want_tool)
            print(f"    [!] {step_label} did not call {want_tool}; retrying once")
            # Reaching here means the turn contained no tool_use blocks (only
            # offered tools can be called), so appending it as-is is safe.
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": f"You must call {want_tool} exactly once. Call it now."})
    agent_log.warning("[WARN] %s did not call %s after retry; aborting", step_label, want_tool)
    return None, response


def _run_tool_calls(items: list, user_input: str, evidence: dict, executed: set,
                    agent_log, tool_log):
    """Validate, dedupe, and execute a batch of {"tool", "input"} items.
    Calls run in parallel — every tool is pure network I/O. Results land in
    `evidence` keyed by tool_name(input); `executed` tracks keys across
    batches so the follow-up round never repeats a call."""
    runnable = []
    for item in items:
        if (not isinstance(item, dict)
                or not isinstance(item.get("tool"), str)
                or not isinstance(item.get("input"), dict)):
            agent_log.warning("[WARN] Skipping malformed plan item: %r", item)
            print(f"    [!] Skipping malformed plan item: {item!r}")
            continue
        tool_name, tool_input = item["tool"], item["input"]
        if tool_name not in INVESTIGATION_TOOL_NAMES:
            agent_log.warning("[WARN] Skipping unknown tool in plan: %s", tool_name)
            print(f"    [!] Skipping unknown tool: {tool_name}")
            continue
        key = f"{tool_name}({json.dumps(tool_input, sort_keys=True)})"
        if key in executed:
            agent_log.warning("[WARN] Duplicate plan entry for %s; skipping repeated call", tool_name)
            print(f"    [!] Skipping duplicate call to {tool_name}")
            continue
        executed.add(key)
        runnable.append((key, tool_name, tool_input))

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_TOOLS) as pool:
        futures = []
        for key, tool_name, tool_input in runnable:
            tool_log.info("[TOOL]   %s  input=%s", tool_name, json.dumps(tool_input))
            print(f"[*] Calling {tool_name}({json.dumps(tool_input)})")
            futures.append((key, tool_name,
                            pool.submit(execute_tool, tool_name, tool_input, tool_log, user_input)))
        for key, tool_name, future in futures:
            result = future.result()
            preview = result[:150] + ("..." if len(result) > 150 else "")
            tool_log.info("[RESULT] %s  (%d chars) %s", tool_name, len(result), preview)
            print(f"    -> {preview}")
            evidence[key] = result


def _plan_followups(evidence: dict, executed: set) -> list:
    """Step 2b: re-extract IOCs from the gathered evidence (redirect targets,
    rDNS hostnames, etc.) and build deterministic follow-up calls for any not
    yet checked. Shared-infrastructure domains are skipped — clean results on
    them carry no signal. Capped at MAX_FOLLOWUP_CALLS, single round."""
    discovered = ioc_extractor.run("\n".join(evidence.values()))
    candidates = []
    for url in discovered["urls"]:
        host_domain = ioc_extractor._root_domain(urlparse(url).hostname or "")
        if host_domain in ioc_extractor.SHARED_INFRA:
            continue
        candidates.append({"tool": "check_url_reputation", "input": {"url": url}})
    for ip in discovered["ips"]:
        candidates.append({"tool": "check_ip_reputation", "input": {"ip": ip}})
    for domain in discovered["domains"]:
        if domain in ioc_extractor.SHARED_INFRA:
            continue
        candidates.append({"tool": "check_domain_reputation", "input": {"domain": domain}})
    pending = [
        c for c in candidates
        if f"{c['tool']}({json.dumps(c['input'], sort_keys=True)})" not in executed
    ]
    return pending[:MAX_FOLLOWUP_CALLS]


def run_chain(user_input: str):
    agent_log, tool_log = setup_loggers()

    iocs = ioc_extractor.run(user_input)
    agent_log.info("[START] IOCs=%s  model=%s  mode=chain", json.dumps(iocs), MODEL)
    print(f"[*] Extracted IOCs: {json.dumps(iocs)}")

    # ── Step 1: Triage ──────────────────────────────────────────────────────
    # Claude receives raw input + IOCs and returns a structured investigation
    # plan via produce_triage_plan. tool_choice="any" forces the tool call so
    # the plan is always machine-parseable rather than free text.
    print("[*] Step 1: Triage — building investigation plan")
    plan, _ = _forced_tool_call(
        "STEP 1", TRIAGE_PROMPT, [TRIAGE_TOOL],
        (
            f"Raw input:\n{user_input}\n\n"
            f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
            "Produce the investigation plan."
        ),
        "produce_triage_plan", agent_log,
    )
    if plan is None:
        print("WARNING: triage step did not produce a plan. Aborting.")
        return

    tools_needed = plan.get("tools_needed")
    if not isinstance(tools_needed, list):
        agent_log.warning("[WARN] Step 1 plan missing or malformed 'tools_needed'; aborting")
        print("WARNING: triage plan missing 'tools_needed'. Aborting.")
        return

    agent_log.info("[STEP 1] plan=%s", json.dumps(plan))
    print(f"[*] Plan: {len(tools_needed)} tool call(s)")

    # ── Step 2: Gather ──────────────────────────────────────────────────────
    # Python executes the plan. No API call. Claude has no role here — the
    # plan fully determines what gets run; calls execute in parallel.
    print("[*] Step 2: Gather — executing tool calls")
    evidence = {}
    executed = set()
    _run_tool_calls(tools_needed, user_input, evidence, executed, agent_log, tool_log)
    agent_log.info("[STEP 2] gathered %d evidence item(s)", len(evidence))

    # ── Step 2b: Follow-up ──────────────────────────────────────────────────
    # Feedback edge: IOCs that only surface in tool results (redirect targets,
    # rDNS hostnames from Shodan, hop IPs) get one bounded follow-up round.
    # Deterministic — no API call; Python maps IOC type -> tool.
    followups = _plan_followups(evidence, executed)
    if followups:
        print(f"[*] Step 2b: Follow-up — {len(followups)} new IOC(s) discovered in evidence")
        _run_tool_calls(followups, user_input, evidence, executed, agent_log, tool_log)
        agent_log.info("[STEP 2b] evidence now %d item(s)", len(evidence))

    # ── Step 3: Verdict ─────────────────────────────────────────────────────
    # Claude receives the full evidence bundle and must call submit_verdict.
    # tool_choice="any" with only submit_verdict offered forces structured output.
    print("[*] Step 3: Verdict — synthesizing evidence")
    evidence_block = "\n\n".join(f"{k}:\n{v}" for k, v in evidence.items())
    submit_verdict_tool = next((t for t in TOOLS if t["name"] == "submit_verdict"), None)
    if submit_verdict_tool is None:
        agent_log.error("[ERROR] submit_verdict not found in TOOLS; aborting")
        print("ERROR: submit_verdict tool definition missing from TOOLS.")
        return
    verdict, verdict_resp = _forced_tool_call(
        "STEP 3", VERDICT_PROMPT, [submit_verdict_tool],
        (
            f"Raw input:\n{user_input}\n\n"
            f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
            f"Tool results:\n{evidence_block}\n\n"
            "Call submit_verdict with your verdict."
        ),
        "submit_verdict", agent_log,
    )
    if verdict is None:
        print("WARNING: verdict step did not produce a verdict. Review logs/ for full trace.")
        return

    for block in verdict_resp.content:
        if getattr(block, "type", None) == "text" and block.text.strip():
            print(f"[Claude] {block.text.strip()}")
    agent_log.info(
        "[VERDICT] verdict=%s  confidence=%s",
        verdict.get("verdict"), verdict.get("confidence"),
    )
    print_verdict(verdict, agent_log)


def get_input() -> str:
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("Paste email or URL (Ctrl+D when done):")
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    return "\n".join(lines)


if __name__ == "__main__":
    user_input = get_input()
    run_chain(user_input)
