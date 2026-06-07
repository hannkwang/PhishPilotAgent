import json
import os
import sys
import time
import anthropic
from config import MODEL, MAX_TOKENS, MAX_ITERATIONS, check_keys, setup_loggers
from tools import ioc_extractor, urlscan, abuseipdb, virustotal, header_parser, defang

check_keys()
client = anthropic.Anthropic()

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
        "description": "Parse email headers for SPF, DKIM, DMARC results and routing hop analysis. Call only if raw email headers are present.",
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_headers": {"type": "string", "description": "Raw email header block"}
            },
            "required": ["raw_headers"],
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
                            ],
                        },
                        "input": {
                            "type": "object",
                            "description": "Input parameters for the tool (e.g. {\"url\": \"https://example.com\"})",
                        },
                    },
                    "required": ["tool", "input"],
                },
            },
        },
        "required": ["tools_needed"],
    },
}


def execute_tool(name: str, tool_input: dict, tool_log) -> str:
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
            tool_log.error("[ERROR] Unknown tool: %s", name)
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        tool_log.error("[ERROR] %s raised: %s", name, e, exc_info=True)
        return json.dumps({"error": str(e), "tool": name})


def print_verdict(v: dict, agent_log):
    agent_log.info(
        "[VERDICT] verdict=%s  confidence=%s  action=%s",
        v["verdict"], v["confidence"], defang.defang(v["recommended_action"]),
    )
    for e in v["evidence"]:
        agent_log.info("[VERDICT]   evidence: %s", defang.defang(e))
    print("\n" + "=" * 50)
    print(f"VERDICT:    {v['verdict']}")
    print(f"CONFIDENCE: {v['confidence']}")
    print("EVIDENCE:")
    for e in v["evidence"]:
        print(f"  - {defang.defang(e)}")
    print(f"ACTION:     {defang.defang(v['recommended_action'])}")
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
                    result = execute_tool(block.name, block.input, tool_log)
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
    t0 = time.monotonic()
    triage_resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=TRIAGE_PROMPT,
        tools=[TRIAGE_TOOL],
        tool_choice={"type": "any"},
        messages=[{
            "role": "user",
            "content": (
                f"Raw input:\n{user_input}\n\n"
                f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
                "Produce the investigation plan."
            ),
        }],
    )
    elapsed = time.monotonic() - t0
    usage = triage_resp.usage
    agent_log.info(
        "[STEP 1] stop_reason=%s  tokens=in:%d out:%d  latency=%.2fs",
        triage_resp.stop_reason, usage.input_tokens, usage.output_tokens, elapsed,
    )

    plan = None
    for block in triage_resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "produce_triage_plan":
            plan = block.input
            break
    if plan is None:
        agent_log.warning("[WARN] Step 1 did not return a triage plan; aborting")
        print("WARNING: triage step did not produce a plan. Aborting.")
        return

    agent_log.info("[STEP 1] plan=%s", json.dumps(plan))
    print(f"[*] Plan: {len(plan['tools_needed'])} tool call(s)")

    # ── Step 2: Gather ──────────────────────────────────────────────────────
    # Python executes each tool call from the plan in sequence. No API call.
    # Claude has no role here — the plan fully determines what gets run.
    print("[*] Step 2: Gather — executing tool calls")
    evidence = {}
    for item in plan["tools_needed"]:
        tool_name = item["tool"]
        tool_input = item["input"]
        tool_log.info("[TOOL]   %s  input=%s", tool_name, json.dumps(tool_input))
        print(f"[*] Calling {tool_name}({json.dumps(tool_input)})")
        result = execute_tool(tool_name, tool_input, tool_log)
        preview = result[:150] + ("..." if len(result) > 150 else "")
        tool_log.info("[RESULT] %s  (%d chars) %s", tool_name, len(result), preview)
        print(f"    -> {preview}")
        evidence[f"{tool_name}({json.dumps(tool_input)})"] = result

    agent_log.info("[STEP 2] gathered %d evidence item(s)", len(evidence))

    # ── Step 3: Verdict ─────────────────────────────────────────────────────
    # Claude receives the full evidence bundle and must call submit_verdict.
    # tool_choice="any" with only submit_verdict offered forces structured output.
    print("[*] Step 3: Verdict — synthesizing evidence")
    evidence_block = "\n\n".join(f"{k}:\n{v}" for k, v in evidence.items())
    submit_verdict_tool = next(t for t in TOOLS if t["name"] == "submit_verdict")
    t0 = time.monotonic()
    verdict_resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=VERDICT_PROMPT,
        tools=[submit_verdict_tool],
        tool_choice={"type": "any"},
        messages=[{
            "role": "user",
            "content": (
                f"Raw input:\n{user_input}\n\n"
                f"Pre-extracted IOCs:\n{json.dumps(iocs, indent=2)}\n\n"
                f"Tool results:\n{evidence_block}\n\n"
                "Call submit_verdict with your verdict."
            ),
        }],
    )
    elapsed = time.monotonic() - t0
    usage = verdict_resp.usage
    agent_log.info(
        "[STEP 3] stop_reason=%s  tokens=in:%d out:%d  latency=%.2fs",
        verdict_resp.stop_reason, usage.input_tokens, usage.output_tokens, elapsed,
    )

    for block in verdict_resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "submit_verdict":
            agent_log.info(
                "[VERDICT] verdict=%s  confidence=%s",
                block.input.get("verdict"), block.input.get("confidence"),
            )
            print_verdict(block.input, agent_log)
            return

    agent_log.warning("[WARN] Step 3 did not call submit_verdict")
    print("WARNING: verdict step did not produce a verdict. Review logs/ for full trace.")


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
