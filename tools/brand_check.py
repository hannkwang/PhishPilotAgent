import json
import html as html_lib
import re
from email.utils import parseaddr
from typing import Optional
from urllib.parse import urlparse
import tldextract

from .ioc_extractor import SHARED_INFRA, decode_email_body, extract_html_links

# Reports the facts needed to judge brand impersonation; interpretation is
# left to the verdict step. The classic phish pattern: display name and
# hotlinked logo assets claim a brand (e.g. Mashreq), while the actual sender
# domain is unrelated (e.g. tdi.tc).


def _registrable(host: str) -> Optional[str]:
    ext = tldextract.extract(host.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def _url_domain(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
        return _registrable(host) if host else None
    except Exception:
        return None


def run(raw_email: str) -> str:
    try:
        msg, body = decode_email_body(raw_email)
        if msg is None:
            return json.dumps({
                "error": "input does not look like a raw email (no header lines found)"
            })

        display_name, sender_addr = parseaddr(msg.get("From", ""))
        sender_domain = (
            _registrable(sender_addr.rsplit("@", 1)[1]) if "@" in sender_addr else None
        )

        body = html_lib.unescape(body)
        hrefs, srcs = extract_html_links(body)
        link_domains = sorted({d for d in (_url_domain(u) for u in hrefs) if d})
        image_domains = sorted({d for d in (_url_domain(u) for u in srcs) if d})

        # Brand assets served from a domain that is neither the sender's nor
        # shared infrastructure — strong impersonation tell.
        hotlinked_brand_domains = [
            d for d in image_domains
            if d != sender_domain and d not in SHARED_INFRA
        ]
        link_domains_not_sender = [
            d for d in link_domains
            if d != sender_domain and d not in SHARED_INFRA
        ]

        name_tokens = re.findall(r"[a-z0-9]{3,}", (display_name or "").lower())
        display_name_matches_sender = bool(
            sender_domain and any(tok in sender_domain for tok in name_tokens)
        )

        return json.dumps({
            "from_display_name": display_name,
            "sender_address": sender_addr,
            "sender_domain": sender_domain,
            "subject": msg.get("Subject", ""),
            "display_name_matches_sender_domain": display_name_matches_sender,
            "body_link_domains": link_domains,
            "body_image_domains": image_domains,
            "brand_assets_hotlinked_from": hotlinked_brand_domains,
            "link_domains_other_than_sender": link_domains_not_sender,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})
