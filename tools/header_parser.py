import re
import json
import email as email_lib
from email.utils import parseaddr
from typing import Optional
import tldextract

AUTH_PAIR_RE = re.compile(r'(\w+)=(pass|fail|none|neutral|softfail|temperror|permerror)', re.IGNORECASE)
RECEIVED_FROM_RE = re.compile(
    r'from\s+(\S+)\s+\((\S+)\s+\[([^\]]+)\]', re.IGNORECASE
)
BCL_RE = re.compile(r'BCL:(\d+)', re.IGNORECASE)


def _parse_auth(header_value: str) -> dict:
    results = {}
    for key, val in AUTH_PAIR_RE.findall(header_value):
        k = key.lower()
        if k in ("spf", "dkim", "dmarc"):
            results[k] = val.lower()
    return results


def _registrable_domain(address: str) -> Optional[str]:
    """Registrable root of the domain in an email address, or None."""
    if "@" not in address:
        return None
    ext = tldextract.extract(address.rsplit("@", 1)[1].lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def _int_or_none(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def run(raw_headers: str) -> str:
    try:
        msg = email_lib.message_from_string(raw_headers + "\n\n")

        auth: dict = {}
        for h in msg.get_all("Authentication-Results") or []:
            for k, v in _parse_auth(h).items():
                auth.setdefault(k, v)  # first (outermost MTA) header wins

        hops = []
        for h in msg.get_all("Received") or []:
            m = RECEIVED_FROM_RE.search(h)
            if m:
                hops.append({
                    "from_host": m.group(1),
                    "rdns": m.group(2),
                    "ip": m.group(3),
                })

        from_hdr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        display_name, from_addr = parseaddr(from_hdr)
        from_domain = _registrable_domain(from_addr)
        reply_to_domain = _registrable_domain(parseaddr(reply_to)[1])
        return_path_domain = _registrable_domain(parseaddr(return_path)[1])

        # Vendor spam verdicts already stamped on the message (Microsoft EOP):
        # SCL >= 5 means the receiving filter classified it as spam; BCL is
        # the bulk-sender score. Free evidence — surface it.
        scl = _int_or_none(msg.get("X-MS-Exchange-Organization-SCL"))
        bcl = None
        antispam = msg.get("X-Microsoft-Antispam", "")
        m = BCL_RE.search(antispam)
        if m:
            bcl = int(m.group(1))

        return json.dumps({
            "spf": auth.get("spf", "not_found"),
            "dkim": auth.get("dkim", "not_found"),
            "dmarc": auth.get("dmarc", "not_found"),
            "from": from_hdr,
            "from_display_name": display_name,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": bool(
                reply_to_domain and from_domain and reply_to_domain != from_domain
            ),
            "return_path": return_path,
            "return_path_domain": return_path_domain,
            "return_path_mismatch": bool(
                return_path_domain and from_domain and return_path_domain != from_domain
            ),
            "subject": msg.get("Subject", ""),
            "vendor_spam_score_scl": scl,
            "vendor_bulk_score_bcl": bcl,
            "hops": hops,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})
