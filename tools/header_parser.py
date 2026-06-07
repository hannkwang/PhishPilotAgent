import re
import json
import email as email_lib

AUTH_PAIR_RE = re.compile(r'(\w+)=(pass|fail|none|neutral|softfail|temperror|permerror)', re.IGNORECASE)
RECEIVED_FROM_RE = re.compile(
    r'from\s+(\S+)\s+\((\S+)\s+\[([^\]]+)\]', re.IGNORECASE
)


def _parse_auth(header_value: str) -> dict:
    results = {}
    for key, val in AUTH_PAIR_RE.findall(header_value):
        k = key.lower()
        if k in ("spf", "dkim", "dmarc"):
            results[k] = val.lower()
    return results


def run(raw_headers: str) -> str:
    try:
        msg = email_lib.message_from_string(raw_headers + "\n\n")

        auth: dict = {}
        for h in msg.get_all("Authentication-Results") or []:
            auth.update(_parse_auth(h))

        hops = []
        for h in msg.get_all("Received") or []:
            m = RECEIVED_FROM_RE.search(h)
            if m:
                hops.append({
                    "from_host": m.group(1),
                    "rdns": m.group(2),
                    "ip": m.group(3),
                })

        return json.dumps({
            "spf": auth.get("spf", "not_found"),
            "dkim": auth.get("dkim", "not_found"),
            "dmarc": auth.get("dmarc", "not_found"),
            "from": msg.get("From", ""),
            "reply_to": msg.get("Reply-To", ""),
            "return_path": msg.get("Return-Path", ""),
            "subject": msg.get("Subject", ""),
            "hops": hops,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})
