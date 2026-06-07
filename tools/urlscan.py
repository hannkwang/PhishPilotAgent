import json
import socket
from urllib.parse import urlparse
import tldextract

# DNS-based blocklist checks — completely keyless.
# A DNS query to <domain>.<dnsbl> that resolves = listed.
# NXDOMAIN (gaierror) = not listed.
DNSBLS = [
    ("Spamhaus_DBL", "{domain}.dbl.spamhaus.org"),
    ("SURBL",        "{domain}.multi.surbl.org"),
    # URIBL dropped: returns 127.0.0.1 for all queries via public DNS resolvers
]

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "account",
    "banking", "paypal", "amazon", "microsoft", "apple",
    "signin", "password", "credential", "wallet",
]


def _check_dnsbl(domain: str, template: str) -> bool:
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(template.format(domain=domain))
        return True
    except socket.gaierror:
        return False


def _root_domain(url: str) -> str:
    try:
        host = urlparse(url).hostname or url
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return host
    except Exception:
        return url


def run(url: str) -> str:
    try:
        domain = _root_domain(url)
        hits = {name: _check_dnsbl(domain, tmpl) for name, tmpl in DNSBLS}
        url_lower = url.lower()
        keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

        return json.dumps({
            "url": url,
            "domain": domain,
            "dnsbl_hits": hits,
            "any_dnsbl_listed": any(hits.values()),
            "suspicious_keywords": keyword_hits,
            "subdomain_count": url.count(".") - 1,
        })
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
