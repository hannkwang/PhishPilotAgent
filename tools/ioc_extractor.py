import base64
import binascii
import html as html_lib
import re
from email import message_from_string
from email.message import Message
from html.parser import HTMLParser
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import tldextract

URL_RE = re.compile(r'https?://[^\s<>"\'`\[\]{}|\\^~]+', re.IGNORECASE)
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
PRIVATE_RE = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)'
)
HEADER_LINE_RE = re.compile(
    r'^(?:Received|From|Subject|Return-Path|Content-Type|MIME-Version|Authentication-Results):',
    re.IGNORECASE | re.MULTILINE,
)

# Registrable domains of shared infrastructure that phishing emails routinely
# launder links and assets through. Clean reputation on these carries no
# signal about the email itself; they are tagged so triage can deprioritize
# them and the verdict step can discount them.
SHARED_INFRA = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "bing.com", "microsoft.com", "outlook.com", "office.com", "office365.com",
    "live.com", "hotmail.com", "windows.net", "azureedge.net",
    "apple.com", "icloud.com",
    "amazonaws.com", "cloudfront.net", "akamaized.net", "akamai.net",
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com",
    "w3.org",
}


def _refang(text: str) -> str:
    return (text
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[.]", ".")
            .replace("[@]", "@")
            .replace("[at]", "@"))


def _root_domain(host: str) -> Optional[str]:
    ext = tldextract.extract(host.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


class _LinkCollector(HTMLParser):
    """Collect href/src attribute values from HTML. HTMLParser unescapes
    entities in attribute values (&amp; -> &), which regex scanning of raw
    HTML would miss."""

    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if not value:
                continue
            if key == "href":
                self.hrefs.append(value.strip())
            elif key == "src":
                self.srcs.append(value.strip())


def extract_html_links(html_text: str) -> Tuple[list, list]:
    """Return (hrefs, srcs) found in an HTML document."""
    collector = _LinkCollector()
    try:
        collector.feed(html_text)
    except Exception:
        pass
    return collector.hrefs, collector.srcs


def decode_email_body(text: str) -> Tuple[Optional[Message], str]:
    """If `text` looks like a raw email, parse it and return (Message,
    decoded_body_text). Decodes quoted-printable and base64 transfer
    encodings — phishing payload URLs are usually invisible without this.
    Returns (None, "") for non-email input."""
    if not HEADER_LINE_RE.search(text):
        return None, ""
    msg = message_from_string(text)
    if not msg.keys():
        return None, ""
    chunks = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if not ctype.startswith("text/"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            chunks.append(payload.decode(charset, errors="replace"))
        except LookupError:
            chunks.append(payload.decode("utf-8", errors="replace"))
    return msg, "\n".join(chunks)


def _b64url_decode(data: str) -> Optional[str]:
    data = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def unwrap_redirect(url: str) -> Optional[str]:
    """Decode one layer of a known redirector / link-wrapper. Returns the
    embedded target URL, or None if `url` is not a recognized wrapper.
    Phishers hide the real destination behind these, so reputation checks
    must run against the target, not the (clean, shared-infra) wrapper."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        qs = parse_qs(parsed.query)

        # Bing click-tracking open redirect: /ck/a?...&u=a1<base64url>
        if host.endswith("bing.com") and parsed.path.startswith("/ck/"):
            u = qs.get("u", [None])[0]
            if u and u[:2] == "a1":
                decoded = _b64url_decode(u[2:])
                if decoded and decoded.lower().startswith(("http://", "https://")):
                    return decoded

        # Microsoft Safe Links: <region>.safelinks.protection.outlook.com/?url=...
        if host.endswith("safelinks.protection.outlook.com"):
            target = qs.get("url", [None])[0]
            if target:
                return unquote(target)

        # Google redirect: google.com/url?q=... or url=...
        if host in ("google.com", "www.google.com") and parsed.path == "/url":
            for key in ("q", "url"):
                target = qs.get(key, [None])[0]
                if target and target.lower().startswith(("http://", "https://")):
                    return unquote(target)

        # Proofpoint urldefense v3: /v3/__<url>__;...
        if "urldefense" in host:
            m = re.search(r'/v3/__(https?:.+?)__;', url)
            if m:
                return m.group(1)

        return None
    except Exception:
        return None


def run(text: str) -> dict:
    text = _refang(text)

    msg, body_text = decode_email_body(text)
    hrefs, srcs = [], []
    if msg is not None and body_text:
        # Scan headers + decoded body. Skipping the raw (still-encoded) body
        # avoids harvesting quoted-printable-mangled URL fragments.
        body_text = html_lib.unescape(body_text)
        scan_texts = [text.split("\n\n", 1)[0], body_text]
        hrefs, srcs = extract_html_links(body_text)
    else:
        scan_texts = [text]

    urls = set()
    for chunk in scan_texts:
        urls |= {m.group(0).rstrip(".,;)>\"'") for m in URL_RE.finditer(chunk)}
    for link in hrefs + srcs:
        if link.lower().startswith(("http://", "https://")):
            urls.add(link.rstrip(".,;)>\"'"))

    # Unwrap known redirectors; bounded in case wrappers nest.
    redirects = []
    frontier = list(urls)
    for _ in range(3):
        newly_found = []
        for u in frontier:
            target = unwrap_redirect(u)
            if target and target not in urls:
                redirects.append({"wrapper": u, "target": target})
                urls.add(target)
                newly_found.append(target)
        if not newly_found:
            break
        frontier = newly_found

    ips = set()
    emails = set()
    for chunk in scan_texts:
        ips |= {ip for ip in IPV4_RE.findall(chunk) if not PRIVATE_RE.match(ip)}
        emails |= {m.group(0).lower() for m in EMAIL_RE.finditer(chunk)}

    domains = set()
    for url in urls:
        try:
            host = urlparse(url).hostname or ""
            d = _root_domain(host)
            if d:
                domains.add(d)
        except Exception:
            pass
    for email_addr in emails:
        if "@" in email_addr:
            d = _root_domain(email_addr.split("@")[1])
            if d:
                domains.add(d)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "emails": sorted(emails),
        "redirects": redirects,
        "shared_infra_domains": sorted(d for d in domains if d in SHARED_INFRA),
    }
