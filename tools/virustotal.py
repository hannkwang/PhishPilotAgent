import json
import socket
from typing import Optional
from datetime import datetime, timezone
from .http import SESSION

# DNS-based domain blocklist checks — keyless.
DOMAIN_DNSBLS = [
    ("Spamhaus_DBL", "{domain}.dbl.spamhaus.org"),
    ("SURBL",        "{domain}.multi.surbl.org"),
    # URIBL dropped: returns 127.0.0.1 for all queries via public DNS resolvers
]

# RDAP servers by TLD — used instead of rdap.org (Cloudflare-blocked)
TLD_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/domain/{domain}",
    "net": "https://rdap.verisign.com/net/v1/domain/{domain}",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/{domain}",
}


def _check_dnsbl(domain: str, template: str) -> bool:
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(template.format(domain=domain))
        return True
    except (socket.gaierror, socket.timeout):
        return False


def _rdap_url(domain: str) -> Optional[str]:
    parts = domain.rsplit(".", 1)
    tld = parts[1].lower() if len(parts) > 1 else ""
    template = TLD_RDAP.get(tld)
    return template.format(domain=domain) if template else None


def run(domain: str) -> str:
    try:
        hits = {name: _check_dnsbl(domain, tmpl) for name, tmpl in DOMAIN_DNSBLS}

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
