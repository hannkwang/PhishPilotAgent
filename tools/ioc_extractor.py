import re
from typing import Optional
from urllib.parse import urlparse
import tldextract

URL_RE = re.compile(r'https?://[^\s<>"\'`\[\]{}|\\^~]+', re.IGNORECASE)
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
PRIVATE_RE = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)'
)


def _refang(text: str) -> str:
    return (text
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[.]", ".")
            .replace("[@]", "@")
            .replace("[at]", "@"))


def _root_domain(host: str) -> Optional[str]:
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def run(text: str) -> dict:
    text = _refang(text)

    urls = list({m.group(0).rstrip(".,;)>\"'") for m in URL_RE.finditer(text)})

    ips = list({
        ip for ip in IPV4_RE.findall(text)
        if not PRIVATE_RE.match(ip)
    })

    emails = list({m.group(0) for m in EMAIL_RE.finditer(text)})

    domains: set[str] = set()
    for url in urls:
        try:
            host = urlparse(url).hostname or ""
            d = _root_domain(host)
            if d:
                domains.add(d)
        except Exception:
            pass
    for email in emails:
        if "@" in email:
            d = _root_domain(email.split("@")[1])
            if d:
                domains.add(d)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "emails": sorted(emails),
    }
