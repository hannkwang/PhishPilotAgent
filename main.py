import json
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

SYSTEM_PROMPT = open("prompts/system_prompt.txt").read()


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

        if response.stop_reason == "max_tokens":
            agent_log.warning("[WARN] Response hit max_tokens on iteration %d; continuing", iteration + 1)
            print("WARNING: response hit max_tokens; continuing loop.")
            continue

        if response.stop_reason == "tool_use":
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

    agent_log.warning("[WARN] Hit MAX_ITERATIONS (%d) without a verdict", MAX_ITERATIONS)
    print("WARNING: hit MAX_ITERATIONS without a verdict. Review logs/ for full trace.")


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
    run_agent(user_input)
