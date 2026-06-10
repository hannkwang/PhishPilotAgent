import json
from urllib.parse import urlparse
import tldextract
from .dnsbl import check as dnsbl_check

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "account",
    "banking", "paypal", "amazon", "microsoft", "apple",
    "signin", "password", "credential", "wallet",
]


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
        hits = dnsbl_check(domain)
        url_lower = url.lower()
        keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

        parsed_host = urlparse(url).hostname or ""
        subdomain = tldextract.extract(parsed_host).subdomain
        subdomain_count = subdomain.count(".") + 1 if subdomain else 0

        return json.dumps({
            "url": url,
            "domain": domain,
            "dnsbl_hits": hits,
            "any_dnsbl_listed": any(hits.values()),
            "suspicious_keywords": keyword_hits,
            "subdomain_count": subdomain_count,
        })
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
