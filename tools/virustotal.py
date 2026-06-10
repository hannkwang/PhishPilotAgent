import json
import threading
from typing import Optional
from datetime import datetime, timezone
from .dnsbl import check as dnsbl_check
from .http import SESSION

# IANA RDAP bootstrap registry: maps every TLD to its RDAP server, so domain
# age works beyond .com/.net/.org (phishing senders favor exotic TLDs).
# Fetched once per process, ~150KB. rdap.org is avoided (Cloudflare-blocked).
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

# Fallback if the bootstrap fetch fails.
TLD_RDAP_FALLBACK = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
}

_rdap_map: Optional[dict] = None
_rdap_lock = threading.Lock()


def _rdap_servers() -> dict:
    global _rdap_map
    with _rdap_lock:
        if _rdap_map is None:
            try:
                resp = SESSION.get(IANA_RDAP_BOOTSTRAP, timeout=10)
                resp.raise_for_status()
                mapping = {}
                for tlds, servers in resp.json().get("services", []):
                    for tld in tlds:
                        if servers:
                            mapping[tld.lower()] = servers[0]
                _rdap_map = mapping
            except Exception:
                _rdap_map = {}
        return _rdap_map


def _rdap_url(domain: str) -> Optional[str]:
    parts = domain.rsplit(".", 1)
    tld = parts[1].lower() if len(parts) > 1 else ""
    base = _rdap_servers().get(tld) or TLD_RDAP_FALLBACK.get(tld)
    if base:
        return base.rstrip("/") + f"/domain/{domain}"
    return None


def run(domain: str) -> str:
    try:
        hits = dnsbl_check(domain)

        age_days = None
        registrar = None
        rdap_url = _rdap_url(domain)
        if rdap_url:
            rdap_resp = SESSION.get(rdap_url, timeout=10)
            if rdap_resp.ok:
                rdap = rdap_resp.json()
                for event in rdap.get("events", []):
                    if event.get("eventAction") == "registration":
                        try:
                            reg_date = datetime.fromisoformat(
                                event["eventDate"].replace("Z", "+00:00")
                            )
                            age_days = (datetime.now(timezone.utc) - reg_date).days
                        except Exception:
                            pass
                entities = rdap.get("entities", [])
                if entities:
                    vcard = entities[0].get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn" and len(field) > 3:
                                registrar = field[3]
                                break

        return json.dumps({
            "domain": domain,
            "dnsbl_hits": hits,
            "any_dnsbl_listed": any(hits.values()),
            "domain_age_days": age_days,
            "registrar": registrar,
        })
    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
