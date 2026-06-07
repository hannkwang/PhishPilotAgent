import json
from .http import SESSION

# ip-api.com — keyless IP geolocation + proxy/VPN/hosting detection (HTTP, 45 req/min)
# Shodan InternetDB — keyless open ports + vuln tags (HTTPS, updated weekly)

def run(ip: str) -> str:
    try:
        ipapi_resp = SESSION.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,isp,org,as,proxy,hosting,mobile"},
            timeout=10,
        )
        ipapi = ipapi_resp.json() if ipapi_resp.ok else {}

        shodan_resp = SESSION.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10,
        )
        shodan = shodan_resp.json() if shodan_resp.ok else {}

        ipapi_ok = ipapi.get("status") == "success"
        return json.dumps({
            "ip": ip,
            "country": ipapi.get("country"),
            "isp": ipapi.get("isp"),
            "org": ipapi.get("org"),
            "asn": ipapi.get("as"),
            "proxy_or_vpn": ipapi.get("proxy") if ipapi_ok else None,
            "hosting_or_datacenter": ipapi.get("hosting") if ipapi_ok else None,
            "open_ports": shodan.get("ports", []),
            "vulns": shodan.get("vulns", []),
            "shodan_tags": shodan.get("tags", []),
            "hostnames": shodan.get("hostnames", []),
        })
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})
