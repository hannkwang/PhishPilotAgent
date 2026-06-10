import socket

# DNS-based blocklist checks — completely keyless.
# A DNS query to <domain>.<dnsbl> that resolves means *something*; the returned
# A record must be validated against the blocklist's documented "listed" range:
#   - Spamhaus DBL: 127.0.1.x = listed; 127.255.255.x = query error (e.g. the
#     query went through a public/open resolver and was refused). Treating any
#     resolution as a hit turns those error codes into false positives.
#   - SURBL: 127.0.0.x bitmask = listed, except 127.0.0.1 which SURBL reserves
#     to signal a problem with the query, never a listing.
# NXDOMAIN (gaierror) = not listed.
# URIBL deliberately omitted: returns 127.0.0.1 for all queries via public DNS.
DNSBLS = [
    ("Spamhaus_DBL", "{domain}.dbl.spamhaus.org", "127.0.1."),
    ("SURBL",        "{domain}.multi.surbl.org",  "127.0.0."),
]


def _listed(addr: str, listed_prefix: str) -> bool:
    if addr == "127.0.0.1":
        return False
    return addr.startswith(listed_prefix)


def check(domain: str) -> dict:
    """Return {blocklist_name: bool} for each configured DNSBL."""
    hits = {}
    for name, template, listed_prefix in DNSBLS:
        try:
            socket.setdefaulttimeout(5)
            addr = socket.gethostbyname(template.format(domain=domain))
            hits[name] = _listed(addr, listed_prefix)
        except (socket.gaierror, socket.timeout):
            hits[name] = False
    return hits
