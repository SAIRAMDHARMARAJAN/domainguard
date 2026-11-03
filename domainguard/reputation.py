"""Optional, read-only reputation and infrastructure checks for public link checks."""
from __future__ import annotations

import base64
import json
import socket
import urllib.error
import urllib.request


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def virustotal_lookup(url: str, api_key: str, timeout: float = 6) -> dict:
    """Read an existing VirusTotal URL analysis; never submit or fetch the URL."""
    if not api_key:
        return {"status": "not_configured", "points": 0, "evidence": []}
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read())
    except (OSError, urllib.error.HTTPError, ValueError):
        return {"status": "unavailable", "points": 0, "evidence": ["external reputation lookup unavailable"]}
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious:
        return {"status": "malicious", "points": min(25, 10 + malicious * 2),
                "evidence": [f"VirusTotal reports {malicious} malicious engine result(s)"]}
    if suspicious:
        return {"status": "suspicious", "points": min(15, 5 + suspicious),
                "evidence": [f"VirusTotal reports {suspicious} suspicious engine result(s)"]}
    return {"status": "clean", "points": 0, "evidence": ["VirusTotal reports no malicious or suspicious results"]}


def infrastructure_checks(host: str) -> dict:
    """Check URL structure and DNS only; do not connect to the submitted host."""
    points = 0
    evidence = []
    if len(host) > 100:
        points += 3
        evidence.append("unusually long hostname")
    if host.count(".") >= 4:
        points += 3
        evidence.append("deep subdomain structure")
    try:
        import dns.resolver
        dns.resolver.resolve(host, "A", lifetime=3)
    except Exception:
        points += 5
        evidence.append("hostname has no resolvable DNS address")
    return {"points": min(10, points), "evidence": evidence}